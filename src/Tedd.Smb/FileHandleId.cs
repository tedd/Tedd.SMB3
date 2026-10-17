namespace Tedd.Smb;

/// <summary>The two opaque 64-bit halves of an SMB3 file identifier.</summary>
/// <remarks>Value keys avoid allocating hexadecimal strings during handle lookup.</remarks>
internal readonly record struct FileHandleId(ulong Persistent, ulong Volatile)
{
    internal static FileHandleId Read(ReadOnlySpan<byte> bytes) => new(Wire.ReadUInt64LittleEndian(bytes, 0), Wire.ReadUInt64LittleEndian(bytes, sizeof(ulong)));
}
