namespace Tedd.SMB3;

/// <summary>Bounded MS-XCA LZNT1 chunks and unchained SMB 3.1.1 compression transforms.</summary>
internal static class SmbCompression
{
    internal const byte Prefix = 0xfc;
    private const int HeaderSize = 16, ChunkSize = 4096;

    internal static byte[] Compress(byte[] packet)
    {
        if (packet.Length < 1024) return packet;
        using var output = new MemoryStream();
        output.Write(new byte[HeaderSize]);
        for (int start = 0; start < packet.Length; start += ChunkSize)
        {
            var chunk = packet.AsSpan(start, Math.Min(ChunkSize, packet.Length - start));
            byte[] encoded = Encode(chunk);
            bool compressed = encoded.Length < chunk.Length;
            var data = compressed ? encoded.AsSpan() : chunk;
            ushort header = (ushort)((compressed ? 0xb000 : 0x3000) | (data.Length - 1));
            output.WriteByte((byte)header); output.WriteByte((byte)(header >> 8)); output.Write(data);
        }
        if (output.Length >= packet.Length) return packet;
        byte[] result = output.ToArray();
        Wire.WriteUInt32LittleEndian(result, 0, 0x424d53fc);
        Wire.WriteUInt32LittleEndian(result, 4, (uint)packet.Length);
        Wire.WriteUInt16LittleEndian(result, 8, 1);
        return result;
    }

    internal static byte[] Decompress(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < HeaderSize || Wire.ReadUInt32LittleEndian(packet, 0) != 0x424d53fc ||
            Wire.ReadUInt16LittleEndian(packet, 8) != 1 || Wire.ReadUInt16LittleEndian(packet, 10) != 0)
            throw new SmbException(NtStatus.InvalidParameter);
        uint size = Wire.ReadUInt32LittleEndian(packet, 4), prefix = Wire.ReadUInt32LittleEndian(packet, 12);
        if (prefix > packet.Length - HeaderSize || size > SmbLimits.MaxFrameSize || prefix > SmbLimits.MaxFrameSize - size ||
            size + prefix < Smb3Header.Size)
            throw new SmbException(NtStatus.InvalidParameter);
        var result = new byte[checked((int)(size + prefix))];
        packet.Slice(HeaderSize, (int)prefix).CopyTo(result);
        Decode(packet[(HeaderSize + (int)prefix)..], result.AsSpan((int)prefix));
        // A transform contains SMB commands, never another compression/encryption transform.
        if (Wire.ReadUInt32LittleEndian(result, 0) != Smb3Header.ProtocolId) throw new SmbException(NtStatus.InvalidParameter);
        return result;
    }

    internal static void Decode(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int source = 0, target = 0;
        while (source < input.Length)
        {
            if (input.Length - source < 2) throw new SmbException(NtStatus.InvalidParameter);
            int header = input[source] | input[source + 1] << 8;
            source += 2;
            if (header == 0 && source == input.Length) break;
            int count = (header & 0xfff) + 1;
            if ((header & 0x7000) != 0x3000 || count > input.Length - source)
                throw new SmbException(NtStatus.InvalidParameter);
            int end = source + count, start = target;
            if ((header & 0x8000) == 0)
            {
                if (count > output.Length - target) throw new SmbException(NtStatus.InvalidParameter);
                input.Slice(source, count).CopyTo(output[target..]); target += count; source = end;
            }
            else while (source < end)
            {
                byte flags = input[source++];
                for (int bit = 0; bit < 8 && source < end; bit++)
                {
                    if ((flags & (1 << bit)) == 0)
                    {
                        if (target >= output.Length || target - start >= ChunkSize) throw new SmbException(NtStatus.InvalidParameter);
                        output[target++] = input[source++];
                    }
                    else
                    {
                        if (end - source < 2) throw new SmbException(NtStatus.InvalidParameter);
                        int word = input[source] | input[source + 1] << 8; source += 2;
                        int shift = Shift(target - start), length = (word & ((1 << shift) - 1)) + 3, distance = (word >> shift) + 1;
                        if (distance > target - start || length > output.Length - target || length > ChunkSize - (target - start))
                            throw new SmbException(NtStatus.InvalidParameter);
                        // Overlapping copies must advance one byte at a time (MS-XCA 2.3.4).
                        for (int i = 0; i < length; i++) { output[target] = output[target - distance]; target++; }
                    }
                }
            }
            if (source < input.Length && target - start != ChunkSize && !(input.Length - source == 2 && input[source] == 0 && input[source + 1] == 0))
                throw new SmbException(NtStatus.InvalidParameter);
        }
        if (target != output.Length) throw new SmbException(NtStatus.InvalidParameter);
    }

    private static int Shift(int position)
    {
        int shift = 12;
        while (shift > 4 && (1 << (16 - shift)) < position) shift--;
        return shift;
    }
    private static int Hash(ReadOnlySpan<byte> data, int position) => ((data[position] * 251 + data[position + 1]) * 251 + data[position + 2]) & 0xfff;
    private static byte[] Encode(ReadOnlySpan<byte> chunk)
    {
        var latest = new int[4096]; Array.Fill(latest, -1);
        var output = new byte[ChunkSize + ChunkSize / 8];
        int position = 0, used = 0;
        while (position < chunk.Length)
        {
            int flagPosition = used++; byte flags = 0;
            for (int bit = 0; bit < 8 && position < chunk.Length; bit++)
            {
                int length = 0, distance = 0, shift = Shift(position);
                if (position + 2 < chunk.Length)
                {
                    int candidate = latest[Hash(chunk, position)];
                    distance = position - candidate;
                    if (candidate >= 0 && distance <= (1 << (16 - shift)))
                    {
                        int maximum = Math.Min(chunk.Length - position, (1 << shift) + 2);
                        while (length < maximum && chunk[candidate + length] == chunk[position + length]) length++;
                    }
                }
                int consumed = length >= 3 ? length : 1;
                if (length >= 3)
                {
                    flags |= (byte)(1 << bit);
                    int word = ((distance - 1) << shift) | (length - 3);
                    output[used++] = (byte)word; output[used++] = (byte)(word >> 8);
                }
                else output[used++] = chunk[position];
                for (int i = position; i < position + consumed && i + 2 < chunk.Length; i++) latest[Hash(chunk, i)] = i;
                position += consumed;
            }
            output[flagPosition] = flags;
        }
        return output[..used];
    }
}
