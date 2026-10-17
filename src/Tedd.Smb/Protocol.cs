using System.Buffers.Binary;
using System.Text;

namespace Tedd.Smb;

/// <summary>Little-endian field access and checked SMB packet construction.</summary>
internal static class Wire
{
    private static readonly UnicodeEncoding StrictUnicode = new(false, false, true);
    internal static ushort ReadUInt16LittleEndian(ReadOnlySpan<byte> buffer, int offset) => BinaryPrimitives.ReadUInt16LittleEndian(buffer[offset..]);
    internal static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> buffer, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(buffer[offset..]);
    internal static ulong ReadUInt64LittleEndian(ReadOnlySpan<byte> buffer, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(buffer[offset..]);
    internal static void WriteUInt16LittleEndian(Span<byte> buffer, int offset, int value) => BinaryPrimitives.WriteUInt16LittleEndian(buffer[offset..], checked((ushort)value));
    internal static void WriteUInt32LittleEndian(Span<byte> buffer, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(buffer[offset..], value);
    internal static void WriteUInt64LittleEndian(Span<byte> buffer, int offset, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(buffer[offset..], value);
    internal static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> b, int o, int n)
    {
        // Subtraction avoids overflowing o + n on hostile offsets and lengths.
        if (o < 0 || n < 0 || o > b.Length || n > b.Length - o)
            throw new SmbException(NtStatus.InvalidParameter);
        return b.Slice(o, n);
    }

    internal static string Text(ReadOnlySpan<byte> b)
    {
        if ((b.Length & 1) != 0)
            throw new SmbException(NtStatus.InvalidParameter);
        return StrictUnicode.GetString(b);
    }

    internal static int Align(int n) => checked((n + 7) & ~7);
    internal static byte[] Join(params byte[][] pieces)
    {
        int length = 0;
        foreach (byte[] piece in pieces)
            length = checked(length + piece.Length);
        var result = new byte[length];
        int p = 0;
        foreach (var x in pieces)
        {
            x.CopyTo(result, p);
            p += x.Length;
        }

        return result;
    }

    // Span overloads avoid a params array and accept slices without temporary arrays.
    internal static byte[] Join(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var result = new byte[checked(first.Length + second.Length)];
        first.CopyTo(result);
        second.CopyTo(result.AsSpan(first.Length));
        return result;
    }

    internal static byte[] Join(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
    {
        var result = new byte[checked(first.Length + second.Length + third.Length)];
        first.CopyTo(result);
        second.CopyTo(result.AsSpan(first.Length));
        third.CopyTo(result.AsSpan(first.Length + second.Length));
        return result;
    }

    internal static byte[] Header(ushort command, ulong message, ulong session = 0, uint tree = 0)
    {
        var b = new byte[Smb2Header.Size];
        WriteHeader(b, command, message, session, tree);
        return b;
    }

    internal static byte[] Packet(ushort command, ulong message, ulong session, uint tree, ReadOnlySpan<byte> body)
    {
        var packet = new byte[checked(Smb2Header.Size + body.Length)];
        WriteHeader(packet, command, message, session, tree);
        body.CopyTo(packet.AsSpan(Smb2Header.Size));
        return packet;
    }

    private static void WriteHeader(Span<byte> b, ushort command, ulong message, ulong session, uint tree)
    {
        WriteUInt32LittleEndian(b, Smb2Header.ProtocolIdOffset, Smb2Header.ProtocolId);
        WriteUInt16LittleEndian(b, Smb2Header.StructureSizeOffset, Smb2Header.Size);
        WriteUInt16LittleEndian(b, Smb2Header.CreditChargeOffset, 1);
        WriteUInt16LittleEndian(b, Smb2Header.CommandOffset, command);
        WriteUInt16LittleEndian(b, Smb2Header.CreditsOffset, SmbLimits.MaxCredits);
        WriteUInt64LittleEndian(b, Smb2Header.MessageIdOffset, message);
        WriteUInt32LittleEndian(b, Smb2Header.ProcessIdOffset, SmbLimits.DefaultProcessId);
        WriteUInt32LittleEndian(b, Smb2Header.TreeIdOffset, tree);
        WriteUInt64LittleEndian(b, Smb2Header.SessionIdOffset, session);
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
}

/// <summary>An SMB operation failure retaining the server's NTSTATUS value.</summary>
public sealed class SmbException : IOException
{
    /// <summary>The protocol status returned by the peer or local validator.</summary>
    public uint NtStatus { get; }

    /// <summary>Creates an exception for a specific NTSTATUS value.</summary>
    public SmbException(uint status) : base($"SMB operation failed: NTSTATUS 0x{status:X8}.") => NtStatus = status;
}
