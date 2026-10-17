using System.Text;

namespace Tedd.Smb;

internal sealed class RpcService
{
    private static readonly byte[] Srv = Convert.FromHexString("C84F324B7016D30112785A47BF6EE18803000000");
    private static readonly byte[] Ndr = Convert.FromHexString("045D888AEB1CC9119FE808002B10486002000000");
    private byte[] pending = [], fragments = [];
    private byte[]? firstFragment;
    private readonly HashSet<ushort> contexts = [];
    internal byte[] Feed(byte[] input, string share)
    {
        if (input.Length > 65536 - pending.Length) throw new SmbException(Status.InvalidParameter);
        pending = Wire.Join(pending, input); byte[] output = [];
        while (pending.Length >= 16)
        {
            int n = Wire.U16(pending, 8); if (n < 16) throw new SmbException(Status.InvalidParameter); if (n > pending.Length) break;
            if (output.Length != 0) throw new SmbException(0xc00000ae);
            var packet = pending[..n]; pending = pending[n..];
            if (packet[2] == 0)
            {
                if (packet.Length < 24) throw new SmbException(Status.InvalidParameter);
                if ((packet[3] & 1) != 0) { if (firstFragment != null) throw new SmbException(Status.InvalidParameter); firstFragment = packet[..24]; fragments = []; }
                if (firstFragment == null || !packet.AsSpan(12, 4).SequenceEqual(firstFragment.AsSpan(12, 4)) || !packet.AsSpan(20, 4).SequenceEqual(firstFragment.AsSpan(20, 4)) || packet.Length - 24 > 65535 - 24 - fragments.Length || Wire.U16(packet, 10) != 0) throw new SmbException(Status.InvalidParameter);
                fragments = Wire.Join(fragments, packet[24..]);
                if ((packet[3] & 2) == 0) continue;
                packet = Wire.Join(firstFragment, fragments); packet[3] = 3; Wire.W16(packet, 8, packet.Length); firstFragment = null; fragments = [];
            }
            output = Process(packet, share);
        }
        return output;
    }
    private byte[] Process(byte[] r, string share)
    {
        if (r.Length < 16 || r.Length > 65535 || r[0] != 5 || r[1] != 0 || (r[3] & 3) != 3 || (r[3] & ~0x17) != 0 || r[4] != 0x10 || Wire.U16(r, 8) != r.Length || Wire.U16(r, 10) != 0) throw new SmbException(Status.InvalidParameter);
        byte[] Finish(byte[] b, byte type)
        { b[0] = 5; b[2] = type; b[3] = 3; b[4] = 0x10; Wire.W16(b, 8, b.Length); Wire.W32(b, 12, Wire.U32(r, 12)); return b; }
        if (r[2] == 11)
        {
            if (r.Length < 28 || r[24] is 0 or > 8) throw new SmbException(Status.InvalidParameter);
            int p = 28; var results = new List<byte[]>(); contexts.Clear();
            for (int i = 0; i < r[24]; i++)
            {
                var h = Wire.Slice(r, p, 24); int count = h[2]; bool accepted = false;
                if (count is < 1 or > 8) throw new SmbException(Status.InvalidParameter);
                for (int j = 0; j < count; j++) if (h[4..].SequenceEqual(Srv) && Wire.Slice(r, p + 24 + j * 20, 20).SequenceEqual(Ndr)) accepted = true;
                var result = new byte[24]; if (accepted) { Ndr.CopyTo(result, 4); contexts.Add(Wire.U16(h, 0)); } else { Wire.W16(result, 0, 2); Wire.W16(result, 2, 2); }
                results.Add(result); p += 24 + count * 20;
            }
            if (p != r.Length) throw new SmbException(Status.InvalidParameter);
            var endpoint = Encoding.ASCII.GetBytes("\\PIPE\\srvsvc\0"); int end = (26 + endpoint.Length + 3) & ~3;
            var b = new byte[end + 4]; Wire.W16(b, 16, 65535); Wire.W16(b, 18, 65535); Wire.W32(b, 20, 1); Wire.W16(b, 24, endpoint.Length); endpoint.CopyTo(b, 26); b[end] = r[24];
            return Finish(Wire.Join(b, Wire.Join(results.ToArray())), 12);
        }
        if (r[2] != 0 || r.Length < 24) throw new SmbException(Status.NotSupported);
        if (!contexts.Contains(Wire.U16(r, 20))) { var fault = new byte[32]; Wire.W16(fault, 20, Wire.U16(r, 20)); Wire.W32(fault, 24, 0x1c00001a); return Finish(fault, 3); }
        var writer = new NdrWriter(); int pos = 24;
        uint Read() { uint n = Wire.U32(Wire.Slice(r, pos, 4), 0); pos += 4; return n; }
        string ReadString()
        {
            uint max = Read(), offset = Read(), count = Read();
            if (count is < 1 or > 1024 || offset > max || count > max - offset) throw new SmbException(Status.InvalidParameter);
            var s = Wire.Slice(r, pos, checked((int)count * 2)); if (Wire.U16(s, s.Length - 2) != 0) throw new SmbException(Status.InvalidParameter);
            string text = Wire.Text(s[..^2]); pos = (pos + s.Length + 3) & ~3; return text;
        }
        uint ptr = Read(); if (ptr != 0) _ = ReadString(); int op = Wire.U16(r, 22); uint status;
        string Name(int i) => i == 0 ? share : "IPC$";
        string Remark(int i) => i == 0 ? "SMB3 files" : "Remote IPC";
        void Fixed(uint level, int i)
        {
            writer.U32((uint)(0x20000 + i * 16));
            if (level == 0) return;
            writer.U32(i == 0 ? 0u : 0x80000003); writer.U32((uint)(0x20004 + i * 16));
            if (level == 2) { writer.U32(0); writer.U32(uint.MaxValue); writer.U32(0); writer.U32((uint)(0x20008 + i * 16)); writer.U32(0); }
        }
        void Strings(uint level, int i) { writer.String(Name(i)); if (level > 0) writer.String(Remark(i)); if (level == 2) writer.String("/"); }
        if (op == 15)
        {
            uint level = Read(), tag = Read(), container = Read(), entries = Read(), buffer = Read();
            if (level != tag || container == 0 || entries != 0 || (buffer != 0 && Read() != 0)) throw new SmbException(Status.InvalidParameter);
            uint maximum = Read(), resumePtr = Read(), resume = resumePtr == 0 ? 0 : Read();
            if (pos != r.Length || level > 2) throw new SmbException(Status.NotSupported);
            int start = (int)Math.Min(resume, 2), count = 0; uint used = 0;
            static uint StringCost(string value) => (uint)(12 + (((value.Length + 1) * 2 + 3) & ~3));
            for (int i = start; i < 2; i++)
            {
                uint cost = 4 + StringCost(Name(i));
                if (level > 0) cost += 8 + StringCost(Remark(i));
                if (level == 2) cost += 20 + StringCost("/");
                if (cost > maximum - used) break; used += cost; count++;
            }
            writer.U32(level); writer.U32(level); writer.U32(0x10000); writer.U32((uint)count); writer.U32(count == 0 ? 0u : 0x10004);
            if (count > 0) { writer.U32((uint)count); for (int i = start; i < start + count; i++) Fixed(level, i); for (int i = start; i < start + count; i++) Strings(level, i); }
            writer.U32((uint)(2 - start)); writer.U32(resumePtr == 0 ? 0u : 0x10008); if (resumePtr != 0) writer.U32((uint)(start + count)); status = start + count < 2 ? 234u : 0;
        }
        else if (op == 16)
        {
            string name = ReadString(); uint level = Read(); if (pos != r.Length) throw new SmbException(Status.InvalidParameter);
            int index = name.Equals(share, StringComparison.OrdinalIgnoreCase) ? 0 : name.Equals("IPC$", StringComparison.OrdinalIgnoreCase) ? 1 : -1;
            writer.U32(level); if (index < 0) { writer.U32(0); status = 2310; }
            else if (level > 2 && level != 1005) { writer.U32(0); status = 124; }
            else { writer.U32(0x10000); if (level == 1005) writer.U32(index == 0 ? 0x30u : 0); else { Fixed(level, index); Strings(level, index); } status = 0; }
        }
        else
        {
            var fault = new byte[32]; Wire.W16(fault, 20, Wire.U16(r, 20)); Wire.W32(fault, 24, 0x1c010002); return Finish(fault, 3);
        }
        writer.U32(status); var body = writer.Bytes(); var response = new byte[24]; Wire.W32(response, 16, (uint)body.Length); Wire.W16(response, 20, Wire.U16(r, 20)); return Finish(Wire.Join(response, body), 2);
    }
    private sealed class NdrWriter
    {
        private readonly MemoryStream stream = new();
        internal void U32(uint n) { var b = new byte[4]; Wire.W32(b, 0, n); stream.Write(b); }
        internal void String(string s) { U32((uint)s.Length + 1); U32(0); U32((uint)s.Length + 1); stream.Write(Encoding.Unicode.GetBytes(s + "\0")); while ((stream.Position & 3) != 0) stream.WriteByte(0); }
        internal byte[] Bytes() => stream.ToArray();
    }
}
