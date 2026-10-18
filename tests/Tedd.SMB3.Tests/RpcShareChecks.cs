using System.Text;
using Tedd.SMB3;

internal static class RpcShareChecks
{
    internal static void Run()
    {
        var names = Enumerable.Range(0, 256).Select(i => i.ToString("D3") + new string('x', 77)).ToArray();
        var rpc = new RpcService();
        var bind = Header(11, 72);
        Wire.WriteUInt16LittleEndian(bind, 16, 1024); Wire.WriteUInt16LittleEndian(bind, 18, 1024);
        bind[24] = 1; bind[30] = 1;
        Convert.FromHexString("C84F324B7016D30112785A47BF6EE18803000000").CopyTo(bind, 32);
        Convert.FromHexString("045D888AEB1CC9119FE808002B10486002000000").CopyTo(bind, 52);
        byte[] ack = rpc.Feed(bind, names);
        if (ack[2] != 12 || Wire.ReadUInt16LittleEndian(ack, 16) != 1024) throw new Exception("RPC fragment negotiation failed.");
        var results = new List<string>();
        uint resume = 0;
        int pages = 0, fragments = 0;
        while (true)
        {
            // Independent NDR32 level-2 enumeration fixture with a non-null resume pointer.
            var request = Header(0, 64);
            Wire.WriteUInt32LittleEndian(request, 16, 36);
            Wire.WriteUInt16LittleEndian(request, 22, 15);
            uint[] stub = [0, 2, 2, 1, 0, 0, uint.MaxValue, 1, resume];
            Array.Resize(ref request, 24 + stub.Length * 4);
            Wire.WriteUInt16LittleEndian(request, 8, request.Length);
            for (int i = 0; i < stub.Length; i++) Wire.WriteUInt32LittleEndian(request, 24 + i * 4, stub[i]);
            byte[] response = rpc.Feed(request, names);
            using var payload = new MemoryStream();
            for (int offset = 0; offset < response.Length;)
            {
                int length = Wire.ReadUInt16LittleEndian(response, offset + 8);
                if (length > 1024 || length < 24 || offset + length > response.Length || response[offset + 2] != 2)
                    throw new Exception("RPC fragment bounds failed.");
                bool first = (response[offset + 3] & 1) != 0, last = (response[offset + 3] & 2) != 0;
                if (first != (offset == 0) || last != (offset + length == response.Length)) throw new Exception("RPC fragment flags failed.");
                payload.Write(response, offset + 24, length - 24);
                offset += length; fragments++;
            }
            byte[] body = payload.ToArray();
            int count = (int)Wire.ReadUInt32LittleEndian(body, 12), p = 24 + count * 32;
            if (count == 0) throw new Exception("RPC enumeration made no progress.");
            string ReadString()
            {
                int characters = (int)Wire.ReadUInt32LittleEndian(body, p + 8);
                string value = Encoding.Unicode.GetString(body, p + 12, characters * 2).TrimEnd('\0');
                p = (p + 12 + characters * 2 + 3) & ~3; return value;
            }
            for (int i = 0; i < count; i++)
            {
                string name = ReadString(); _ = ReadString(); _ = ReadString();
                uint type = Wire.ReadUInt32LittleEndian(body, 24 + i * 32 + 4);
                if (type != (name == "IPC$" ? 0x80000003u : 0u)) throw new Exception("RPC share type mismatch.");
                results.Add(name);
            }
            resume = Wire.ReadUInt32LittleEndian(body, p + 8);
            uint status = Wire.ReadUInt32LittleEndian(body, p + 12);
            pages++;
            if (status == 0) break;
            if (status != 234 || pages > 4) throw new Exception("RPC pagination status failed.");
        }
        if (!results.SequenceEqual(names.Append("IPC$")) || pages < 2 || fragments < 2)
            throw new Exception("RPC multi-share pagination lost entries.");
        Console.WriteLine("PASS 256-share srvsvc enumeration, IPC$ typing, NDR resume pagination and negotiated RPC fragmentation");
    }

    private static byte[] Header(byte type, int length)
    {
        var result = new byte[length];
        result[0] = 5; result[2] = type; result[3] = 3; result[4] = 0x10;
        Wire.WriteUInt16LittleEndian(result, 8, length); Wire.WriteUInt32LittleEndian(result, 12, 1);
        return result;
    }
}
