using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Tedd.Smb;

/// <summary>Maps native identity, times and DOS attributes onto MS-FSCC metadata.</summary>
/// <remarks>Linux xattrs persist SMB fields that POSIX metadata cannot represent.</remarks>
internal static class FileMetadata
{
    private const string TimesAttribute = "user.tedd.smb3.times";
    private const string DosAttribute = "user.tedd.smb3.dos";
    private static class StoredTimes
    {
        internal const int Size = 16;
        internal const int CreationTimeOffset = 0;
        internal const int ChangeTimeOffset = 8;
    }

    private const uint StoredDosAttributes = FileAttributeFlags.Hidden | FileAttributeFlags.Archive;
    private const uint ReportedDosAttributes = FileAttributeFlags.ReadOnly | FileAttributeFlags.Hidden | FileAttributeFlags.System | FileAttributeFlags.Directory | FileAttributeFlags.Archive;
    [DllImport("libc", SetLastError = true)]
    private static extern int statx(int dirfd, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, [Out] byte[] info);
    [DllImport("libc", SetLastError = true)]
    private static extern nint getxattr([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, [Out] byte[] value, nuint size);
    [DllImport("libc", SetLastError = true)]
    private static extern int setxattr([MarshalAs(UnmanagedType.LPUTF8Str)] string path, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, byte[] value, nuint size, int flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, nint security, uint disposition, uint flags, nint template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int cls, [Out] byte[] info, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int cls, byte[] info, uint size);
    private static byte[]? Attribute(string path, string name, int length)
    {
        // Missing/unsupported attributes permit native fallback; malformed values do not.
        var value = new byte[length];
        nint n = getxattr(path, name, value, (nuint)length);
        if (n == length)
            return value;
        int error = Marshal.GetLastPInvokeError();
        if (n < 0 && error is LinuxError.NoData or LinuxError.NotSupported)
            return null; // ENODATA / ENOTSUP
        if (n >= 0 || error == LinuxError.Range)
            throw new IOException("Invalid SMB filesystem metadata.");
        throw new IOException("Cannot read SMB filesystem metadata.", new Win32Exception(error));
    }

    private static void Store(string path, string name, byte[] value)
    {
        if (setxattr(path, name, value, (nuint)value.Length, 0) == 0)
            return;
        int error = Marshal.GetLastPInvokeError();
        if (error == LinuxError.NotSupported)
            throw new SmbException(NtStatus.NotSupported);
        throw new IOException("Cannot persist SMB filesystem metadata.", new Win32Exception(error));
    }

    internal static byte[] Identity(string path)
    {
        // Hash native object identity, not the path, so handles survive rename.
        if (OperatingSystem.IsLinux())
        {
            var info = new byte[LinuxStatx.Size];
            if (statx(LinuxStatx.AtFdcwd, path, LinuxStatx.AtSymlinkNoFollow, LinuxStatx.BasicStatsMask, info) != 0)
                throw new IOException("Cannot query file identity.", new Win32Exception(Marshal.GetLastPInvokeError()));
            var identity = Wire.Join(info.AsSpan(LinuxStatx.DeviceIdOffset, LinuxStatx.DeviceIdSize), info.AsSpan(LinuxStatx.InodeOffset, sizeof(ulong)));
            return SHA256.HashData(identity)[..FileInternalInformation.Size];
        }

        if (OperatingSystem.IsWindows())
        {
            using var h = CreateFileW(path, 0, FileShareAccess.All, 0, WindowsCreationDisposition.OpenExisting, WindowsFileFlags.BackupSemantics | WindowsFileFlags.OpenReparsePoint, 0);
            if (h.IsInvalid)
                throw new IOException("Cannot open file identity.", new Win32Exception(Marshal.GetLastPInvokeError()));
            var info = new byte[WindowsFileIdInfo.Size];
            if (!GetFileInformationByHandleEx(h, WindowsFileInfoClass.FileIdInfo, info, WindowsFileIdInfo.Size))
                throw new IOException("Cannot query file identity.", new Win32Exception(Marshal.GetLastPInvokeError()));
            return SHA256.HashData(info)[..FileInternalInformation.Size];
        }

        return SHA256.HashData(Encoding.UTF8.GetBytes(path))[..FileInternalInformation.Size];
    }

    internal static void Times(byte[] b, int p, string path, FileSystemInfo info)
    {
        if (OperatingSystem.IsWindows())
        {
            using var handle = CreateFileW(path, 0, FileShareAccess.All, 0, WindowsCreationDisposition.OpenExisting, WindowsFileFlags.BackupSemantics | WindowsFileFlags.OpenReparsePoint, 0);
            var basic = new byte[FileBasicInformation.Size];
            if (handle.IsInvalid || !GetFileInformationByHandleEx(handle, WindowsFileInfoClass.FileBasicInfo, basic, FileBasicInformation.Size))
                throw new IOException("Cannot query file timestamps.", new Win32Exception(Marshal.GetLastPInvokeError()));
            basic.AsSpan(0, FileBasicInformation.FileAttributesOffset).CopyTo(b.AsSpan(p));
            return;
        }

        ulong creation = (ulong)info.CreationTimeUtc.ToFileTimeUtc(), change = (ulong)info.LastWriteTimeUtc.ToFileTimeUtc();
        if (OperatingSystem.IsLinux())
        {
            var stat = new byte[LinuxStatx.Size];
            if (statx(LinuxStatx.AtFdcwd, path, LinuxStatx.AtSymlinkNoFollow, LinuxStatx.BasicStatsMask, stat) != 0)
                throw new IOException("Cannot query timestamps.", new Win32Exception(Marshal.GetLastPInvokeError()));
            change = checked((ulong)(DateTimeOffset.FromUnixTimeSeconds(checked((long)Wire.ReadUInt64LittleEndian(stat, LinuxStatx.ChangeTimeSecondsOffset))).UtcDateTime.ToFileTimeUtc() + Wire.ReadUInt32LittleEndian(stat, LinuxStatx.ChangeTimeNanosecondsOffset) / TimeSpan.NanosecondsPerTick));
            var metadata = Attribute(path, TimesAttribute, StoredTimes.Size);
            if (metadata != null)
            {
                creation = Wire.ReadUInt64LittleEndian(metadata, StoredTimes.CreationTimeOffset);
                change = Wire.ReadUInt64LittleEndian(metadata, StoredTimes.ChangeTimeOffset);
            }
        }

        Wire.WriteUInt64LittleEndian(b, p, creation);
        Wire.WriteUInt64LittleEndian(b, p + FileBasicInformation.LastAccessTimeOffset, (ulong)info.LastAccessTimeUtc.ToFileTimeUtc());
        Wire.WriteUInt64LittleEndian(b, p + FileBasicInformation.LastWriteTimeOffset, (ulong)info.LastWriteTimeUtc.ToFileTimeUtc());
        Wire.WriteUInt64LittleEndian(b, p + FileBasicInformation.ChangeTimeOffset, change);
    }

    internal static void SetTimes(string path, ReadOnlySpan<byte> data)
    {
        var values = new DateTime?[FileBasicInformation.TimestampCount];
        for (int i = 0; i < FileBasicInformation.TimestampCount; i++)
        {
            ulong t = Wire.ReadUInt64LittleEndian(data, i * sizeof(ulong));
            if (t is not (0 or ulong.MaxValue))
                values[i] = DateTime.FromFileTimeUtc(checked((long)t));
        }

        if (OperatingSystem.IsWindows())
        {
            using var handle = CreateFileW(path, FileAccessMask.WriteAttributes, FileShareAccess.All, 0, WindowsCreationDisposition.OpenExisting, WindowsFileFlags.BackupSemantics | WindowsFileFlags.OpenReparsePoint, 0);
            if (handle.IsInvalid)
                throw new IOException("Cannot open file timestamps.", new Win32Exception(Marshal.GetLastPInvokeError()));
            var basic = new byte[FileBasicInformation.Size];
            data[..FileBasicInformation.FileAttributesOffset].CopyTo(basic);
            if (!SetFileInformationByHandle(handle, WindowsFileInfoClass.FileBasicInfo, basic, FileBasicInformation.Size))
                throw new IOException("Cannot set file timestamps.", new Win32Exception(Marshal.GetLastPInvokeError()));
            return;
        }

        if (OperatingSystem.IsLinux() && (values[0] != null || values[3] != null))
        {
            var b = new byte[FileBasicInformation.FileAttributesOffset];
            Times(b, 0, path, Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path));
            var stored = new byte[StoredTimes.Size];
            Wire.WriteUInt64LittleEndian(stored, StoredTimes.CreationTimeOffset, values[0] is { } c ? (ulong)c.ToFileTimeUtc() : Wire.ReadUInt64LittleEndian(b, FileBasicInformation.CreationTimeOffset));
            Wire.WriteUInt64LittleEndian(stored, StoredTimes.ChangeTimeOffset, values[3] is { } ch ? (ulong)ch.ToFileTimeUtc() : Wire.ReadUInt64LittleEndian(b, FileBasicInformation.ChangeTimeOffset));
            Store(path, TimesAttribute, stored);
        }
        else if (values[0] is { } creation)
            File.SetCreationTimeUtc(path, creation);
        if (values[1] is { } access)
            File.SetLastAccessTimeUtc(path, access);
        if (values[2] is { } write)
            File.SetLastWriteTimeUtc(path, write);
    }

    internal static uint Attributes(string path, FileSystemInfo info)
    {
        uint value = (uint)info.Attributes & ReportedDosAttributes;
        if (OperatingSystem.IsLinux())
        {
            var stored = Attribute(path, DosAttribute, sizeof(uint));
            if (stored != null)
                value = (value & ~StoredDosAttributes) | (Wire.ReadUInt32LittleEndian(stored, 0) & StoredDosAttributes);
        }

        return value == 0 ? FileAttributeFlags.Normal : value;
    }

    internal static void SetAttributes(string path, uint attributes, bool directory)
    {
        if ((attributes & ~SmbLimits.SupportedFileAttributes) != 0)
            throw new SmbException(NtStatus.NotSupported);
        File.SetAttributes(path, (FileAttributes)(attributes & ~FileAttributeFlags.Normal) | (directory ? FileAttributes.Directory : 0));
        if (OperatingSystem.IsLinux())
        {
            var b = new byte[sizeof(uint)];
            Wire.WriteUInt32LittleEndian(b, 0, attributes & StoredDosAttributes);
            try
            {
                Store(path, DosAttribute, b);
            }
            catch (SmbException e) when (e.NtStatus == NtStatus.NotSupported && ((uint)File.GetAttributes(path) & StoredDosAttributes) == (attributes & StoredDosAttributes))
            {
            }
        }
    }

    internal static void Changed(string path, bool archive = false)
    {
        if (!OperatingSystem.IsLinux())
            return;
        var times = Attribute(path, TimesAttribute, StoredTimes.Size);
        if (times != null)
        {
            Wire.WriteUInt64LittleEndian(times, StoredTimes.ChangeTimeOffset, (ulong)DateTime.UtcNow.ToFileTimeUtc());
            Store(path, TimesAttribute, times);
        }

        if (archive && !Directory.Exists(path))
            SetAttributes(path, Attributes(path, new FileInfo(path)) | FileAttributeFlags.Archive, false);
    }

    internal static uint LinkCount(string path)
    {
        if (OperatingSystem.IsLinux())
        {
            var info = new byte[LinuxStatx.Size];
            if (statx(LinuxStatx.AtFdcwd, path, LinuxStatx.AtSymlinkNoFollow, LinuxStatx.BasicStatsMask, info) != 0)
                throw new IOException("Cannot query file links.", new Win32Exception(Marshal.GetLastPInvokeError()));
            return Wire.ReadUInt32LittleEndian(info, LinuxStatx.LinkCountOffset);
        }

        if (OperatingSystem.IsWindows())
        {
            using var h = CreateFileW(path, 0, FileShareAccess.All, 0, WindowsCreationDisposition.OpenExisting, WindowsFileFlags.BackupSemantics | WindowsFileFlags.OpenReparsePoint, 0);
            var info = new byte[FileStandardInformation.Size];
            if (h.IsInvalid || !GetFileInformationByHandleEx(h, WindowsFileInfoClass.FileStandardInfo, info, FileStandardInformation.Size))
                throw new IOException("Cannot query file links.", new Win32Exception(Marshal.GetLastPInvokeError()));
            return Wire.ReadUInt32LittleEndian(info, FileStandardInformation.NumberOfLinksOffset);
        }

        return 1;
    }
}
