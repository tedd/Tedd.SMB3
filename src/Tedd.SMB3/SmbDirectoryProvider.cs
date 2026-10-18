using System.Security.Cryptography;
using System.Text;

namespace Tedd.SMB3;

/// <summary>Directory-backed storage with native Windows metadata or Linux user xattrs.</summary>
/// <remarks>The export must be trusted; path checks cannot prevent hostile local namespace races.</remarks>
public abstract class SmbDirectoryProvider : ISmbShareProvider
{
    public string RootPath { get; }
    private readonly Guid volumeId;

    protected SmbDirectoryProvider(string rootPath)
    {
        RootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootPath));
        if (!Directory.Exists(RootPath))
            throw new DirectoryNotFoundException(RootPath);
        if ((File.GetAttributes(RootPath) & FileAttributes.ReparsePoint) != 0)
            throw new ArgumentException("Export root cannot be a link.", nameof(rootPath));
        volumeId = new Guid(SHA256.HashData(FileMetadata.Identity(RootPath)).AsSpan(0, 16));
    }

    public static SmbDirectoryProvider Create(string rootPath) => OperatingSystem.IsWindows()
        ? new WindowsDirectoryProvider(rootPath) : OperatingSystem.IsLinux()
        ? new LinuxDirectoryProvider(rootPath) : throw new PlatformNotSupportedException();

    public SmbVolumeInfo Volume
    {
        get
        {
            var drive = new DriveInfo(RootPath);
            return new(volumeId, Directory.GetCreationTimeUtc(RootPath), drive.TotalSize,
                drive.AvailableFreeSpace, drive.TotalFreeSpace, SmbLimits.FileSystemName);
        }
    }

    public string ResolvePath(string path)
    {
        string physical = Physical(path);
        string relative = Path.GetRelativePath(RootPath, physical);
        return relative == "." ? "" : relative.Replace(Path.DirectorySeparatorChar, '/');
    }

    private string Physical(string name)
    {
        name = SmbPath.Normalize(name);
        if ((File.GetAttributes(RootPath) & FileAttributes.ReparsePoint) != 0)
            throw new SmbException(NtStatus.AccessDenied);
        string path = RootPath;
        foreach (string part in name.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            string? exact = null, match = null;
            int matches = 0;
            if (Directory.Exists(path))
            {
                foreach (string entry in Directory.EnumerateFileSystemEntries(path))
                {
                    var entryName = Path.GetFileName(entry.AsSpan());
                    if (!entryName.Equals(part, StringComparison.OrdinalIgnoreCase))
                        continue;
                    matches++;
                    match = entry;
                    if (entryName.SequenceEqual(part)) { exact = entry; break; }
                }
            }
            if (exact == null && matches > 1)
                throw new SmbException(NtStatus.ObjectNameCollision);
            path = exact ?? (matches == 1 ? match! : Path.Combine(path, part));
            try
            {
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new SmbException(NtStatus.AccessDenied);
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
        return path;
    }

    public SmbFileMetadata? GetMetadata(string path)
    {
        string physical = Physical(path);
        if (!File.Exists(physical) && !Directory.Exists(physical))
            return null;
        bool directory = Directory.Exists(physical);
        FileSystemInfo info = directory ? new DirectoryInfo(physical) : new FileInfo(physical);
        var times = new byte[FileBasicInformation.FileAttributesOffset];
        FileMetadata.Times(times, 0, physical, info);
        DateTime Time(int p) => DateTime.FromFileTimeUtc(checked((long)Wire.ReadUInt64LittleEndian(times, p)));
        return new(Wire.ReadUInt64LittleEndian(FileMetadata.Identity(physical), 0), directory ? 0 : ((FileInfo)info).Length,
            (FileAttributes)FileMetadata.Attributes(physical, info), Time(0), Time(8), Time(16), Time(24), FileMetadata.LinkCount(physical));
    }

    public IEnumerable<string> EnumerateDirectory(string path)
    {
        foreach (string entry in Directory.EnumerateFileSystemEntries(Physical(path)))
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) == 0)
                yield return Path.GetRelativePath(RootPath, entry).Replace(Path.DirectorySeparatorChar, '/');
    }

    public ISmbFile OpenFile(string path, FileMode mode, FileAccess access, FileShare share, bool writeThrough) =>
        new DirectoryFile(new FileStream(Physical(path), mode, access, share, 1,
            FileOptions.Asynchronous | (writeThrough ? FileOptions.WriteThrough : FileOptions.None)));

    public void CreateDirectory(string path) => Directory.CreateDirectory(Physical(path));
    public void Delete(string path, bool directory)
    {
        if (SmbPath.Normalize(path).Length == 0) throw new SmbException(NtStatus.AccessDenied);
        if (directory) Directory.Delete(Physical(path)); else File.Delete(Physical(path));
    }
    public void Move(string source, string destination, bool directory, bool replace)
    {
        if (SmbPath.Normalize(source).Length == 0 || SmbPath.Normalize(destination).Length == 0)
            throw new SmbException(NtStatus.AccessDenied);
        if (directory) Directory.Move(Physical(source), Physical(destination));
        else File.Move(Physical(source), Physical(destination), replace);
    }

    public void SetMetadata(string path, SmbMetadataUpdate update)
    {
        var times = new byte[FileBasicInformation.Size];
        DateTime?[] values = [update.CreationTimeUtc, update.LastAccessTimeUtc, update.LastWriteTimeUtc, update.ChangeTimeUtc];
        for (int i = 0; i < values.Length; i++)
            if (values[i] is { } value) Wire.WriteUInt64LittleEndian(times, i * sizeof(ulong), checked((ulong)value.ToFileTimeUtc()));
        string physical = Physical(path);
        FileMetadata.SetTimes(physical, times);
        if (update.Attributes is { } attributes)
            FileMetadata.SetAttributes(physical, (uint)attributes, Directory.Exists(physical));
    }
    public void MarkChanged(string path, bool archive) => FileMetadata.Changed(Physical(path), archive);

    private sealed class DirectoryFile(FileStream stream) : ISmbFile
    {
        public long Length => stream.Length;
        public ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken) =>
            RandomAccess.ReadAsync(stream.SafeFileHandle, buffer, offset, cancellationToken);
        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken) =>
            RandomAccess.WriteAsync(stream.SafeFileHandle, buffer, offset, cancellationToken);
        public void SetLength(long length) => stream.SetLength(length);
        public void Flush() => stream.Flush(true);
        public void Dispose() => stream.Dispose();
    }
}

/// <summary>Windows directory provider using native file identities, timestamps, and DOS attributes.</summary>
public sealed class WindowsDirectoryProvider : SmbDirectoryProvider
{
    public WindowsDirectoryProvider(string rootPath) : base(RequireWindows(rootPath)) { }
    private static string RequireWindows(string path) => OperatingSystem.IsWindows() ? path : throw new PlatformNotSupportedException();
}

/// <summary>Linux directory provider using statx identities and user.tedd.smb3.* metadata xattrs.</summary>
public sealed class LinuxDirectoryProvider : SmbDirectoryProvider
{
    public LinuxDirectoryProvider(string rootPath) : base(RequireLinux(rootPath)) { }
    private static string RequireLinux(string path) => OperatingSystem.IsLinux() ? path : throw new PlatformNotSupportedException();
}
