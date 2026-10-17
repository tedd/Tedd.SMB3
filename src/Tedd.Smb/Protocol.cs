using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace Tedd.Smb;

internal static class Wire
{
    internal static ushort ReadUInt16LittleEndian(ReadOnlySpan<byte> buffer, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(buffer[offset..]);
    internal static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> buffer, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(buffer[offset..]);
    internal static ulong ReadUInt64LittleEndian(ReadOnlySpan<byte> buffer, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(buffer[offset..]);
    internal static void WriteUInt16LittleEndian(Span<byte> buffer, int offset, int value) => BinaryPrimitives.WriteUInt16LittleEndian(buffer[offset..], checked((ushort)value));
    internal static void WriteUInt32LittleEndian(Span<byte> buffer, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(buffer[offset..], value);
    internal static void WriteUInt64LittleEndian(Span<byte> buffer, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(buffer[offset..], value);
    internal static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> b, int o, int n)
    {
        if (o < 0 || n < 0 || o > b.Length || n > b.Length - o) throw new SmbException(NtStatus.InvalidParameter);
        return b.Slice(o, n);
    }
    internal static string Text(ReadOnlySpan<byte> b)
    {
        if ((b.Length & 1) != 0) throw new SmbException(NtStatus.InvalidParameter);
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
        var b = new byte[Smb2Header.Size];
        WriteUInt32LittleEndian(b, Smb2Header.ProtocolIdOffset, Smb2Header.ProtocolId);
        WriteUInt16LittleEndian(b, Smb2Header.StructureSizeOffset, Smb2Header.Size);
        WriteUInt16LittleEndian(b, Smb2Header.CreditChargeOffset, 1);
        WriteUInt16LittleEndian(b, Smb2Header.CommandOffset, command);
        WriteUInt16LittleEndian(b, Smb2Header.CreditsOffset, SmbLimits.MaxCredits);
        WriteUInt64LittleEndian(b, Smb2Header.MessageIdOffset, message);
        WriteUInt32LittleEndian(b, Smb2Header.ProcessIdOffset, SmbLimits.DefaultProcessId);
        WriteUInt32LittleEndian(b, Smb2Header.TreeIdOffset, tree);
        WriteUInt64LittleEndian(b, Smb2Header.SessionIdOffset, session);
        return b;
    }
    internal static byte[] CreateSimpleMessage()
    {
        var body = new byte[Smb2SimpleMessage.FixedSize];
        WriteUInt16LittleEndian(body, 0, Smb2SimpleMessage.StructureSize);
        return body;
    }
    internal static void Validate(ReadOnlySpan<byte> b)
    {
        if (b.Length < Smb2Header.Size || ReadUInt32LittleEndian(b, Smb2Header.ProtocolIdOffset) != Smb2Header.ProtocolId || ReadUInt16LittleEndian(b, Smb2Header.StructureSizeOffset) != Smb2Header.Size)
            throw new SmbException(NtStatus.InvalidParameter);
    }
    internal static async Task<byte[]> ReceiveAsync(NetworkStream stream, CancellationToken ct)
    {
        var h = new byte[DirectTcpTransport.HeaderSize];
        await stream.ReadExactlyAsync(h, ct);
        int n = (h[1] << 16) | (h[2] << 8) | h[3];
        if (h[0] != DirectTcpTransport.SessionMessage || n < Smb2TransformHeader.Size || n > SmbLimits.MaxFrameSize) throw new SmbException(NtStatus.InvalidParameter);
        var b = new byte[n];
        await stream.ReadExactlyAsync(b, ct);
        return b;
    }
    internal static async Task SendAsync(NetworkStream stream, byte[] b, CancellationToken ct)
    {
        var packet = new byte[b.Length + DirectTcpTransport.HeaderSize];
        packet[1] = (byte)(b.Length >> 16); packet[2] = (byte)(b.Length >> 8); packet[3] = (byte)b.Length;
        b.CopyTo(packet, DirectTcpTransport.HeaderSize);
        await stream.WriteAsync(packet, ct);
    }
}

public sealed class SmbException : IOException
{
    public uint NtStatus { get; }
    public SmbException(uint status) : base($"SMB operation failed: NTSTATUS 0x{status:X8}.") => NtStatus = status;
}
