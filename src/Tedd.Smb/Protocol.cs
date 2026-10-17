using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace Tedd.Smb;

internal static class Wire
{
    internal static ushort U16(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt16LittleEndian(b[o..]);
    internal static uint U32(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt32LittleEndian(b[o..]);
    internal static ulong U64(ReadOnlySpan<byte> b, int o) => BinaryPrimitives.ReadUInt64LittleEndian(b[o..]);
    internal static void W16(Span<byte> b, int o, int v) => BinaryPrimitives.WriteUInt16LittleEndian(b[o..], checked((ushort)v));
    internal static void W32(Span<byte> b, int o, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b[o..], v);
    internal static void W64(Span<byte> b, int o, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(b[o..], v);
    internal static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> b, int o, int n)
    {
        if (o < 0 || n < 0 || o > b.Length || n > b.Length - o) throw new SmbException(Status.InvalidParameter);
        return b.Slice(o, n);
    }
    internal static string Text(ReadOnlySpan<byte> b)
    {
        if ((b.Length & 1) != 0) throw new SmbException(Status.InvalidParameter);
        return new UnicodeEncoding(false, false, true).GetString(b);
    }
    internal static int Align(int n) => checked((n + 7) & ~7);
    internal static byte[] Join(params byte[][] pieces)
    {
        var result = new byte[pieces.Sum(x => x.Length)];
        int p = 0;
        foreach (var x in pieces) { x.CopyTo(result, p); p += x.Length; }
        return result;
    }
    internal static byte[] Header(ushort command, ulong message, ulong session = 0, uint tree = 0)
    {
        var b = new byte[64];
        b[0] = 0xfe; b[1] = 0x53; b[2] = 0x4d; b[3] = 0x42;
        W16(b, 4, 64); W16(b, 6, 1); W16(b, 12, command); W16(b, 14, 32);
        W64(b, 24, message); W32(b, 32, 0xfeff); W32(b, 36, tree); W64(b, 40, session);
        return b;
    }
    internal static void Validate(ReadOnlySpan<byte> b)
    {
        if (b.Length < 64 || !b[..4].SequenceEqual(new byte[] { 0xfe, 0x53, 0x4d, 0x42 }) || U16(b, 4) != 64)
            throw new SmbException(Status.InvalidParameter);
    }
    internal static async Task<byte[]> ReceiveAsync(NetworkStream stream, CancellationToken ct)
    {
        var h = new byte[4];
        await stream.ReadExactlyAsync(h, ct);
        int n = (h[1] << 16) | (h[2] << 8) | h[3];
        if (h[0] != 0 || n < 52 || n > 4 * 1024 * 1024) throw new SmbException(Status.InvalidParameter);
        var b = new byte[n];
        await stream.ReadExactlyAsync(b, ct);
        return b;
    }
    internal static async Task SendAsync(NetworkStream stream, byte[] b, CancellationToken ct)
    {
        var packet = new byte[b.Length + 4];
        packet[1] = (byte)(b.Length >> 16); packet[2] = (byte)(b.Length >> 8); packet[3] = (byte)b.Length;
        b.CopyTo(packet, 4);
        await stream.WriteAsync(packet, ct);
    }
}

internal static class Status
{
    internal const uint Success = 0, MoreProcessing = 0xc0000016, InvalidParameter = 0xc000000d,
        AccessDenied = 0xc0000022, NotSupported = 0xc00000bb, LogonFailure = 0xc000006d,
        NotFound = 0xc0000034, Collision = 0xc0000035, NoMoreFiles = 0x80000006,
        EndOfFile = 0xc0000011, BufferOverflow = 0x80000005, BufferTooSmall = 0xc0000023,
        InvalidHandle = 0xc0000008, BadNetworkName = 0xc00000cc, SharingViolation = 0xc0000043,
        DirectoryNotEmpty = 0xc0000101, NotDirectory = 0xc0000103, FileIsDirectory = 0xc00000ba,
        InfoLengthMismatch = 0xc0000004, InvalidInfoClass = 0xc0000003;
}

public sealed class SmbException : IOException
{
    public uint NtStatus { get; }
    public SmbException(uint status) : base($"SMB operation failed: NTSTATUS 0x{status:X8}.") => NtStatus = status;
}
