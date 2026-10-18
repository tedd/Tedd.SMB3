using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Tedd.SMB3;

internal static class CompressionChecks
{
    internal static void Run()
    {
        var literal = new byte[10];
        SmbCompression.Decode(Convert.FromHexString("03B002410600"), literal);
        if (literal.Any(x => x != 0x41)) throw new Exception("LZNT1 overlapping backreference fixture failed.");
        foreach (int size in new[] { 1024, 4095, 4096, 4097, 65536 })
        foreach (int pattern in new[] { 0, 1, 2 })
        {
            byte[] packet = pattern == 2 ? RandomNumberGenerator.GetBytes(size) : new byte[size];
            if (pattern == 1) for (int i = 0; i < packet.Length; i++) packet[i] = (byte)(i % 33);
            Wire.WriteUInt32LittleEndian(packet, 0, 0x424d53fe);
            byte[] compressed = SmbCompression.Compress(packet);
            if (compressed[0] == 0xfc && !SmbCompression.Decompress(compressed).AsSpan().SequenceEqual(packet))
                throw new Exception("LZNT1 managed round trip failed.");
            if (!OperatingSystem.IsWindows()) continue;
            if (compressed[0] == 0xfc)
            {
                var decoded = new byte[size];
                byte[] raw = compressed[16..];
                if (RtlDecompressBuffer(2, decoded, decoded.Length, raw, raw.Length, out int used) != 0 || used != size || !decoded.AsSpan().SequenceEqual(packet))
                    throw new Exception("Windows rejected managed LZNT1 output.");
            }
            if (RtlGetCompressionWorkSpaceSize(2, out int workspaceSize, out _) != 0) throw new Exception("Cannot query native codec workspace.");
            nint workspace = Marshal.AllocHGlobal(workspaceSize);
            try
            {
                byte[] native = new byte[size * 2 + 1024];
                int status = RtlCompressBuffer(2, packet, size, native, native.Length, 4096, out int used, workspace);
                if (status != 0) throw new Exception($"Native LZNT1 compressor failed: {status:X8}.");
                byte[] transform = Transform(native.AsSpan(0, used), size);
                if (!SmbCompression.Decompress(transform).AsSpan().SequenceEqual(packet))
                    throw new Exception("Managed decoder rejected Windows LZNT1 output.");
            }
            finally { Marshal.FreeHGlobal(workspace); }
        }
        foreach (var input in new[] { Convert.FromHexString("01B00100"), Convert.FromHexString("01B000"), Convert.FromHexString("003000"), Convert.FromHexString("03B003000000") })
        {
            try { SmbCompression.Decode(input, new byte[64]); }
            catch (SmbException) { continue; }
            throw new Exception("Malformed LZNT1 chunk accepted.");
        }
        byte[] bomb = Transform([0x00, 0x30, 0], int.MaxValue);
        try { _ = SmbCompression.Decompress(bomb); throw new Exception("Oversized compression transform accepted."); }
        catch (SmbException) { }
        Console.WriteLine("PASS LZNT1 overlap, chunk boundaries, malformed input and decompression bounds" +
            (OperatingSystem.IsWindows() ? "; independent Windows native codec in both directions" : ""));
    }

    private static byte[] Transform(ReadOnlySpan<byte> compressed, int size)
    {
        var result = new byte[16 + compressed.Length];
        Wire.WriteUInt32LittleEndian(result, 0, 0x424d53fc);
        Wire.WriteUInt32LittleEndian(result, 4, (uint)size);
        Wire.WriteUInt16LittleEndian(result, 8, 1);
        compressed.CopyTo(result.AsSpan(16)); return result;
    }
    [DllImport("ntdll.dll")] private static extern int RtlDecompressBuffer(ushort format, byte[] output, int outputSize, byte[] input, int inputSize, out int used);
    [DllImport("ntdll.dll")] private static extern int RtlGetCompressionWorkSpaceSize(ushort format, out int workspace, out int fragment);
    [DllImport("ntdll.dll")] private static extern int RtlCompressBuffer(ushort format, byte[] input, int inputSize, byte[] output, int outputSize, int chunkSize, out int used, nint workspace);
}
