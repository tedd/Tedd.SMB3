using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Tedd.Smb;

internal static class FileMetadata
{
    private const string TimesAttribute = "user.tedd.smb3.times", DosAttribute = "user.tedd.smb3.dos";
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
        var value = new byte[length]; nint n = getxattr(path, name, value, (nuint)length);
        if (n == length) return value;
        int error = Marshal.GetLastPInvokeError();
        if (n < 0 && error is 61 or 95) return null; // ENODATA / ENOTSUP
        if (n >= 0 || error == 34) throw new IOException("Invalid SMB filesystem metadata.");
        throw new IOException("Cannot read SMB filesystem metadata.", new Win32Exception(error));
    }
    private static void Store(string path, string name, byte[] value)
    {
        if (setxattr(path, name, value, (nuint)value.Length, 0) == 0) return;
        int error = Marshal.GetLastPInvokeError();
        if (error == 95) throw new SmbException(Status.NotSupported);
        throw new IOException("Cannot persist SMB filesystem metadata.", new Win32Exception(error));
    }
    internal static byte[] Identity(string path)
    {
        if (OperatingSystem.IsLinux())
        {
            var info = new byte[256]; if (statx(-100, path, 0x100, 0x7ff, info) != 0) throw new IOException("Cannot query file identity.", new Win32Exception(Marshal.GetLastPInvokeError()));
            var identity = Wire.Join(info[136..144], info[32..40]); return SHA256.HashData(identity)[..8];
        }
        if (OperatingSystem.IsWindows())
        {
            using var h = CreateFileW(path, 0, 7, 0, 3, 0x02200000, 0); if (h.IsInvalid) throw new IOException("Cannot open file identity.", new Win32Exception(Marshal.GetLastPInvokeError()));
            var info = new byte[24]; if (!GetFileInformationByHandleEx(h, 18, info, 24)) throw new IOException("Cannot query file identity.", new Win32Exception(Marshal.GetLastPInvokeError()));
            return SHA256.HashData(info)[..8];
        }
        return SHA256.HashData(Encoding.UTF8.GetBytes(path))[..8];
    }
    internal static void Times(byte[] b, int p, string path, FileSystemInfo info)
    {
        if (OperatingSystem.IsWindows())
        {
            using var handle = CreateFileW(path, 0, 7, 0, 3, 0x02200000, 0); var basic = new byte[40];
            if (handle.IsInvalid || !GetFileInformationByHandleEx(handle, 0, basic, 40)) throw new IOException("Cannot query file timestamps.", new Win32Exception(Marshal.GetLastPInvokeError()));
            basic.AsSpan(0, 32).CopyTo(b.AsSpan(p)); return;
        }
        ulong creation = (ulong)info.CreationTimeUtc.ToFileTimeUtc(), change = (ulong)info.LastWriteTimeUtc.ToFileTimeUtc();
        if (OperatingSystem.IsLinux())
        {
            var stat = new byte[256];
            if (statx(-100, path, 0x100, 0x7ff, stat) != 0) throw new IOException("Cannot query timestamps.", new Win32Exception(Marshal.GetLastPInvokeError()));
            change = checked((ulong)(DateTimeOffset.FromUnixTimeSeconds(checked((long)Wire.U64(stat, 96))).UtcDateTime.ToFileTimeUtc() + Wire.U32(stat, 104) / 100));
            var metadata = Attribute(path, TimesAttribute, 16);
            if (metadata != null) { creation = Wire.U64(metadata, 0); change = Wire.U64(metadata, 8); }
        }
        Wire.W64(b, p, creation); Wire.W64(b, p + 8, (ulong)info.LastAccessTimeUtc.ToFileTimeUtc());
        Wire.W64(b, p + 16, (ulong)info.LastWriteTimeUtc.ToFileTimeUtc()); Wire.W64(b, p + 24, change);
    }
    internal static void SetTimes(string path, ReadOnlySpan<byte> data)
    {
        var values = new DateTime?[4];
        for (int i = 0; i < 4; i++) { ulong t = Wire.U64(data, i * 8); if (t is not (0 or ulong.MaxValue)) values[i] = DateTime.FromFileTimeUtc(checked((long)t)); }
        if (OperatingSystem.IsWindows())
        {
            using var handle = CreateFileW(path, 0x100, 7, 0, 3, 0x02200000, 0);
            if (handle.IsInvalid) throw new IOException("Cannot open file timestamps.", new Win32Exception(Marshal.GetLastPInvokeError()));
            var basic = new byte[40]; data[..32].CopyTo(basic);
            if (!SetFileInformationByHandle(handle, 0, basic, 40)) throw new IOException("Cannot set file timestamps.", new Win32Exception(Marshal.GetLastPInvokeError()));
            return;
        }
        if (OperatingSystem.IsLinux() && (values[0] != null || values[3] != null))
        {
            var b = new byte[32]; Times(b, 0, path, Directory.Exists(path) ? new DirectoryInfo(path) : new FileInfo(path));
            var stored = new byte[16]; Wire.W64(stored, 0, values[0] is { } c ? (ulong)c.ToFileTimeUtc() : Wire.U64(b, 0)); Wire.W64(stored, 8, values[3] is { } ch ? (ulong)ch.ToFileTimeUtc() : Wire.U64(b, 24)); Store(path, TimesAttribute, stored);
        }
        else if (values[0] is { } creation) File.SetCreationTimeUtc(path, creation);
        if (values[1] is { } access) File.SetLastAccessTimeUtc(path, access);
        if (values[2] is { } write) File.SetLastWriteTimeUtc(path, write);
    }
    internal static uint Attributes(string path, FileSystemInfo info)
    {
        uint value = (uint)info.Attributes & 0x37u;
        if (OperatingSystem.IsLinux()) { var stored = Attribute(path, DosAttribute, 4); if (stored != null) value = (value & ~0x22u) | (Wire.U32(stored, 0) & 0x22); }
        return value == 0 ? 0x80 : value;
    }
    internal static void SetAttributes(string path, uint attributes, bool directory)
    {
        if ((attributes & ~0xb3u) != 0) throw new SmbException(Status.NotSupported);
        File.SetAttributes(path, (FileAttributes)(attributes & ~0x80u) | (directory ? FileAttributes.Directory : 0));
        if (OperatingSystem.IsLinux())
        {
            var b = new byte[4]; Wire.W32(b, 0, attributes & 0x22);
            try { Store(path, DosAttribute, b); }
            catch (SmbException e) when (e.NtStatus == Status.NotSupported && ((uint)File.GetAttributes(path) & 0x22) == (attributes & 0x22)) { }
        }
    }
    internal static void Changed(string path, bool archive = false)
    {
        if (!OperatingSystem.IsLinux()) return;
        var times = Attribute(path, TimesAttribute, 16);
        if (times != null) { Wire.W64(times, 8, (ulong)DateTime.UtcNow.ToFileTimeUtc()); Store(path, TimesAttribute, times); }
        if (archive && !Directory.Exists(path)) SetAttributes(path, Attributes(path, new FileInfo(path)) | 0x20, false);
    }
    internal static uint LinkCount(string path)
    {
        if (OperatingSystem.IsLinux())
        {
            var info = new byte[256]; if (statx(-100, path, 0x100, 0x7ff, info) != 0) throw new IOException("Cannot query file links.", new Win32Exception(Marshal.GetLastPInvokeError())); return Wire.U32(info, 16);
        }
        if (OperatingSystem.IsWindows())
        {
            using var h = CreateFileW(path, 0, 7, 0, 3, 0x02200000, 0); var info = new byte[24];
            if (h.IsInvalid || !GetFileInformationByHandleEx(h, 1, info, 24)) throw new IOException("Cannot query file links.", new Win32Exception(Marshal.GetLastPInvokeError())); return Wire.U32(info, 16);
        }
        return 1;
    }
}
