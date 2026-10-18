namespace Tedd.SMB3;

/// <summary>A named share backed by an application-owned provider. Writes are opt-in.</summary>
public sealed record SmbShare(string Name, ISmbShareProvider Provider)
{
    public bool Writable { get; init; }
    /// <summary>Application authorization for an authenticated principal; required for external authentication.</summary>
    public Func<string, bool>? Authorize { get; init; }
}

/// <summary>Storage for a share. Paths are canonical, slash-separated, share-relative names;
/// the root is the empty string. Providers own their resources and outlive server connections.</summary>
/// <remarks>Namespace and metadata operations execute under the server's file gate. Providers
/// must return stable object IDs across rename, enforce containment, reject links, and throw
/// IOException, UnauthorizedAccessException, NotSupportedException or SmbException on failure.
/// No local filesystem, FileStream, or native file handle is required.</remarks>
public interface ISmbShareProvider
{
    SmbVolumeInfo Volume { get; }
    string ResolvePath(string path);
    SmbFileMetadata? GetMetadata(string path);
    IEnumerable<string> EnumerateDirectory(string path);
    ISmbFile OpenFile(string path, FileMode mode, FileAccess access, FileShare share, bool writeThrough);
    void CreateDirectory(string path);
    void Delete(string path, bool directory);
    void Move(string source, string destination, bool directory, bool replace);
    void SetMetadata(string path, SmbMetadataUpdate update);
    void MarkChanged(string path, bool archive);
}

/// <summary>An open file with positional I/O; implementations must not use a shared cursor.</summary>
public interface ISmbFile : IDisposable
{
    long Length { get; }
    ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken);
    ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken);
    void SetLength(long length);
    void Flush();
}

/// <summary>Stable identity and current metadata in UTC. FileId is scoped by Volume.Id.</summary>
public sealed record SmbFileMetadata(ulong FileId, long Length, FileAttributes Attributes,
    DateTime CreationTimeUtc, DateTime LastAccessTimeUtc, DateTime LastWriteTimeUtc, DateTime ChangeTimeUtc,
    uint LinkCount = 1)
{
    public bool IsDirectory => (Attributes & FileAttributes.Directory) != 0;
}

/// <summary>Null fields leave the corresponding metadata unchanged.</summary>
public sealed record SmbMetadataUpdate(DateTime? CreationTimeUtc = null, DateTime? LastAccessTimeUtc = null,
    DateTime? LastWriteTimeUtc = null, DateTime? ChangeTimeUtc = null, FileAttributes? Attributes = null);

/// <summary>Storage capacity in bytes and a stable, provider-defined volume identity.</summary>
public sealed record SmbVolumeInfo(Guid Id, DateTime CreationTimeUtc, long TotalBytes, long AvailableBytes,
    long FreeBytes, string FileSystemName = "SMB3");

internal static class SmbPath
{
    internal static string Normalize(string name)
    {
        if (name.IndexOf('\0') >= 0 || name.StartsWith('\\') || name.StartsWith('/') || name.Contains(':'))
            throw new SmbException(NtStatus.AccessDenied);
        var parts = name.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (string part in parts)
        {
            if (part is "." or ".." || part.EndsWith(' ') || part.EndsWith('.') || part.Length > SmbLimits.MaxComponentLength ||
                part.Any(c => c < 32 || "<>\"|?*".Contains(c)) || IsReservedDevice(part))
                throw new SmbException(NtStatus.AccessDenied);
        }
        return string.Join('/', parts);
    }

    private static bool IsReservedDevice(ReadOnlySpan<char> component)
    {
        int extension = component.IndexOf('.');
        var basename = (extension < 0 ? component : component[..extension]).TrimEnd(' ');
        if (basename.Equals("CON", StringComparison.OrdinalIgnoreCase) || basename.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            basename.Equals("AUX", StringComparison.OrdinalIgnoreCase) || basename.Equals("NUL", StringComparison.OrdinalIgnoreCase))
            return true;
        return basename.Length == 4 && (basename.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
            basename.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) && "123456789\u00b9\u00b2\u00b3".Contains(basename[3]);
    }
}
