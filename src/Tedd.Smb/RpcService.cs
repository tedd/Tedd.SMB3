using System.Text;

namespace Tedd.Smb;

internal sealed class RpcService
{
    private static readonly byte[] SrvsvcAbstractSyntax = Convert.FromHexString("C84F324B7016D30112785A47BF6EE18803000000");
    private static readonly byte[] Ndr32TransferSyntax = Convert.FromHexString("045D888AEB1CC9119FE808002B10486002000000");
    private byte[] pending = [], fragments = [];
    private byte[]? firstFragment;
    private readonly HashSet<ushort> contexts = [];
    internal byte[] Feed(byte[] input, string share)
    {
        if (input.Length > RpcLimits.MaxBufferedBytes - pending.Length) throw new SmbException(NtStatus.InvalidParameter);
        pending = Wire.Join(pending, input); byte[] output = [];
        while (pending.Length >= RpcHeader.Size)
        {
            int n = Wire.ReadUInt16LittleEndian(pending, RpcHeader.FragmentLengthOffset); if (n < RpcHeader.Size) throw new SmbException(NtStatus.InvalidParameter); if (n > pending.Length) break;
            if (output.Length != 0) throw new SmbException(NtStatus.PipeBusy);
            var packet = pending[..n]; pending = pending[n..];
            if (packet[RpcHeader.PacketTypeOffset] == RpcPacketType.Request)
            {
                if (packet.Length < RpcRequest.HeaderSize) throw new SmbException(NtStatus.InvalidParameter);
                if ((packet[RpcHeader.FlagsOffset] & RpcPacketFlags.FirstFragment) != 0) { if (firstFragment != null) throw new SmbException(NtStatus.InvalidParameter); firstFragment = packet[..RpcRequest.HeaderSize]; fragments = []; }
                if (firstFragment == null || !packet.AsSpan(RpcHeader.CallIdOffset, sizeof(uint)).SequenceEqual(firstFragment.AsSpan(RpcHeader.CallIdOffset, sizeof(uint))) || !packet.AsSpan(RpcRequest.ContextIdOffset, sizeof(uint)).SequenceEqual(firstFragment.AsSpan(RpcRequest.ContextIdOffset, sizeof(uint))) || packet.Length - RpcRequest.HeaderSize > RpcLimits.MaxFragmentSize - RpcRequest.HeaderSize - fragments.Length || Wire.ReadUInt16LittleEndian(packet, RpcHeader.AuthLengthOffset) != 0) throw new SmbException(NtStatus.InvalidParameter);
                fragments = Wire.Join(fragments, packet[RpcRequest.HeaderSize..]);
                if ((packet[RpcHeader.FlagsOffset] & RpcPacketFlags.LastFragment) == 0) continue;
                packet = Wire.Join(firstFragment, fragments); packet[RpcHeader.FlagsOffset] = RpcPacketFlags.CompleteFragment;
                Wire.WriteUInt16LittleEndian(packet, RpcHeader.FragmentLengthOffset, packet.Length); firstFragment = null; fragments = [];
            }
            output = Process(packet, share);
        }
        return output;
    }
    private byte[] Process(byte[] r, string share)
    {
        if (r.Length < RpcHeader.Size || r.Length > RpcLimits.MaxFragmentSize || r[RpcHeader.VersionOffset] != RpcHeader.Version || r[RpcHeader.VersionMinorOffset] != 0 || (r[RpcHeader.FlagsOffset] & RpcPacketFlags.CompleteFragment) != RpcPacketFlags.CompleteFragment || (r[RpcHeader.FlagsOffset] & ~RpcPacketFlags.Supported) != 0 || r[RpcHeader.DataRepresentationOffset] != RpcHeader.LittleEndianDataRepresentation || Wire.ReadUInt16LittleEndian(r, RpcHeader.FragmentLengthOffset) != r.Length || Wire.ReadUInt16LittleEndian(r, RpcHeader.AuthLengthOffset) != 0) throw new SmbException(NtStatus.InvalidParameter);
        byte[] Finish(byte[] b, byte type)
        {
            b[RpcHeader.VersionOffset] = RpcHeader.Version; b[RpcHeader.PacketTypeOffset] = type; b[RpcHeader.FlagsOffset] = RpcPacketFlags.CompleteFragment; b[RpcHeader.DataRepresentationOffset] = RpcHeader.LittleEndianDataRepresentation;
            Wire.WriteUInt16LittleEndian(b, RpcHeader.FragmentLengthOffset, b.Length);
            Wire.WriteUInt32LittleEndian(b, RpcHeader.CallIdOffset, Wire.ReadUInt32LittleEndian(r, RpcHeader.CallIdOffset)); return b;
        }
        if (r[RpcHeader.PacketTypeOffset] == RpcPacketType.Bind)
        {
            if (r.Length < RpcBind.FixedSize || r[RpcBind.ContextCountOffset] is 0 or > RpcLimits.MaxContexts) throw new SmbException(NtStatus.InvalidParameter);
            int p = RpcBind.FixedSize; var results = new List<byte[]>(); contexts.Clear();
            for (int i = 0; i < r[RpcBind.ContextCountOffset]; i++)
            {
                var h = Wire.Slice(r, p, RpcBind.ContextElementFixedSize); int count = h[RpcBind.TransferSyntaxCountOffset]; bool accepted = false;
                if (count is < 1 or > RpcLimits.MaxTransferSyntaxes) throw new SmbException(NtStatus.InvalidParameter);
                for (int j = 0; j < count; j++) if (h[RpcBind.AbstractSyntaxOffset..].SequenceEqual(SrvsvcAbstractSyntax) && Wire.Slice(r, p + RpcBind.ContextElementFixedSize + j * RpcSyntaxIdentifier.Size, RpcSyntaxIdentifier.Size).SequenceEqual(Ndr32TransferSyntax)) accepted = true;
                var result = new byte[RpcBindAck.ResultSize]; if (accepted) { Ndr32TransferSyntax.CopyTo(result, RpcBindAck.TransferSyntaxOffset); contexts.Add(Wire.ReadUInt16LittleEndian(h, RpcBind.ContextIdOffset)); }
                else
                {
                    Wire.WriteUInt16LittleEndian(result, RpcBindAck.ResultOffset, RpcBindAck.ProviderRejection);
                    Wire.WriteUInt16LittleEndian(result, RpcBindAck.ReasonOffset, RpcBindAck.ProposedTransferSyntaxesNotSupported);
                }
                results.Add(result); p += RpcBind.ContextElementFixedSize + count * RpcSyntaxIdentifier.Size;
            }
            if (p != r.Length) throw new SmbException(NtStatus.InvalidParameter);
            var endpoint = Encoding.ASCII.GetBytes("\\PIPE\\srvsvc\0"); int end = (RpcBindAck.FixedSize + endpoint.Length + 3) & ~3;
            var b = new byte[end + RpcBindAck.ResultListHeaderSize];
            Wire.WriteUInt16LittleEndian(b, RpcBindAck.MaxTransmitFragmentOffset, RpcLimits.MaxFragmentSize);
            Wire.WriteUInt16LittleEndian(b, RpcBindAck.MaxReceiveFragmentOffset, RpcLimits.MaxFragmentSize);
            Wire.WriteUInt32LittleEndian(b, RpcBindAck.AssociationGroupIdOffset, 1);
            Wire.WriteUInt16LittleEndian(b, RpcBindAck.SecondaryAddressLengthOffset, endpoint.Length); endpoint.CopyTo(b, RpcBindAck.FixedSize); b[end] = r[RpcBind.ContextCountOffset];
            return Finish(Wire.Join(b, Wire.Join(results.ToArray())), RpcPacketType.BindAck);
        }
        if (r[RpcHeader.PacketTypeOffset] != RpcPacketType.Request || r.Length < RpcRequest.HeaderSize) throw new SmbException(NtStatus.NotSupported);
        if (!contexts.Contains(Wire.ReadUInt16LittleEndian(r, RpcRequest.ContextIdOffset)))
        {
            var fault = new byte[RpcFault.Size];
            Wire.WriteUInt16LittleEndian(fault, RpcFault.ContextIdOffset, Wire.ReadUInt16LittleEndian(r, RpcRequest.ContextIdOffset));
            Wire.WriteUInt32LittleEndian(fault, RpcFault.StatusOffset, RpcFault.ContextMismatch); return Finish(fault, RpcPacketType.Fault);
        }
        var writer = new NdrWriter(); int pos = RpcRequest.HeaderSize;
        uint ReadUInt32() { uint n = Wire.ReadUInt32LittleEndian(Wire.Slice(r, pos, 4), 0); pos += 4; return n; }
        string ReadString()
        {
            uint max = ReadUInt32(), offset = ReadUInt32(), count = ReadUInt32();
            if (count is < 1 or > RpcLimits.MaxStringCharacters || offset > max || count > max - offset) throw new SmbException(NtStatus.InvalidParameter);
            var s = Wire.Slice(r, pos, checked((int)count * 2)); if (Wire.ReadUInt16LittleEndian(s, s.Length - 2) != 0) throw new SmbException(NtStatus.InvalidParameter);
            string text = Wire.Text(s[..^2]); pos = (pos + s.Length + 3) & ~3; return text;
        }
        uint ptr = ReadUInt32(); if (ptr != 0) _ = ReadString(); int op = Wire.ReadUInt16LittleEndian(r, RpcRequest.OpnumOffset); uint status;
        string Name(int i) => i == 0 ? share : "IPC$";
        string Remark(int i) => i == 0 ? "SMB3 files" : "Remote IPC";
        void Fixed(uint level, int i)
        {
            writer.WriteUInt32((uint)(SrvsvcReferent.ShareName + i * SrvsvcReferent.ShareStride));
            if (level == SrvsvcShareInfoLevel.Name) return;
            writer.WriteUInt32(i == 0 ? SrvsvcShareType.DiskTree : SrvsvcShareType.Ipc | SrvsvcShareType.Special); writer.WriteUInt32((uint)(SrvsvcReferent.ShareRemark + i * SrvsvcReferent.ShareStride));
            if (level == SrvsvcShareInfoLevel.Path) { writer.WriteUInt32(0); writer.WriteUInt32(uint.MaxValue); writer.WriteUInt32(0); writer.WriteUInt32((uint)(SrvsvcReferent.SharePath + i * SrvsvcReferent.ShareStride)); writer.WriteUInt32(0); }
        }
        void Strings(uint level, int i) { writer.String(Name(i)); if (level > SrvsvcShareInfoLevel.Name) writer.String(Remark(i)); if (level == SrvsvcShareInfoLevel.Path) writer.String("/"); }
        if (op == SrvsvcOpnum.NetrShareEnum)
        {
            uint level = ReadUInt32(), tag = ReadUInt32(), container = ReadUInt32(), entries = ReadUInt32(), buffer = ReadUInt32();
            if (level != tag || container == 0 || entries != 0 || (buffer != 0 && ReadUInt32() != 0)) throw new SmbException(NtStatus.InvalidParameter);
            uint maximum = ReadUInt32(), resumePtr = ReadUInt32(), resume = resumePtr == 0 ? 0 : ReadUInt32();
            if (pos != r.Length || level > SrvsvcShareInfoLevel.Path) throw new SmbException(NtStatus.NotSupported);
            int start = (int)Math.Min(resume, RpcLimits.ShareCount), count = 0; uint used = 0;
            static uint StringCost(string value) => (uint)(12 + (((value.Length + 1) * 2 + 3) & ~3));
            for (int i = start; i < RpcLimits.ShareCount; i++)
            {
                uint cost = 4 + StringCost(Name(i));
                if (level > SrvsvcShareInfoLevel.Name) cost += 8 + StringCost(Remark(i));
                if (level == SrvsvcShareInfoLevel.Path) cost += 20 + StringCost("/");
                if (cost > maximum - used) break; used += cost; count++;
            }
            writer.WriteUInt32(level); writer.WriteUInt32(level); writer.WriteUInt32(SrvsvcReferent.Container); writer.WriteUInt32((uint)count); writer.WriteUInt32(count == 0 ? 0u : SrvsvcReferent.Buffer);
            if (count > 0) { writer.WriteUInt32((uint)count); for (int i = start; i < start + count; i++) Fixed(level, i); for (int i = start; i < start + count; i++) Strings(level, i); }
            writer.WriteUInt32((uint)(RpcLimits.ShareCount - start)); writer.WriteUInt32(resumePtr == 0 ? 0u : SrvsvcReferent.ResumeHandle); if (resumePtr != 0) writer.WriteUInt32((uint)(start + count)); status = start + count < RpcLimits.ShareCount ? Win32Error.MoreData : Win32Error.Success;
        }
        else if (op == SrvsvcOpnum.NetrShareGetInfo)
        {
            string name = ReadString(); uint level = ReadUInt32(); if (pos != r.Length) throw new SmbException(NtStatus.InvalidParameter);
            int index = name.Equals(share, StringComparison.OrdinalIgnoreCase) ? 0 : name.Equals("IPC$", StringComparison.OrdinalIgnoreCase) ? 1 : -1;
            writer.WriteUInt32(level); if (index < 0) { writer.WriteUInt32(0); status = Win32Error.NetNameNotFound; }
            else if (level > SrvsvcShareInfoLevel.Path && level != SrvsvcShareInfoLevel.Flags) { writer.WriteUInt32(0); status = Win32Error.InvalidLevel; }
            else { writer.WriteUInt32(SrvsvcReferent.Container); if (level == SrvsvcShareInfoLevel.Flags) writer.WriteUInt32(index == 0 ? Smb2ShareFlags.NoCaching : 0); else { Fixed(level, index); Strings(level, index); } status = Win32Error.Success; }
        }
        else
        {
            var fault = new byte[RpcFault.Size];
            Wire.WriteUInt16LittleEndian(fault, RpcFault.ContextIdOffset, Wire.ReadUInt16LittleEndian(r, RpcRequest.ContextIdOffset));
            Wire.WriteUInt32LittleEndian(fault, RpcFault.StatusOffset, RpcFault.OperationRangeError); return Finish(fault, RpcPacketType.Fault);
        }
        writer.WriteUInt32(status); var body = writer.Bytes(); var response = new byte[RpcResponse.HeaderSize];
        Wire.WriteUInt32LittleEndian(response, RpcResponse.AllocationHintOffset, (uint)body.Length);
        Wire.WriteUInt16LittleEndian(response, RpcResponse.ContextIdOffset, Wire.ReadUInt16LittleEndian(r, RpcRequest.ContextIdOffset)); return Finish(Wire.Join(response, body), RpcPacketType.Response);
    }
    private sealed class NdrWriter
    {
        private readonly MemoryStream stream = new();
        internal void WriteUInt32(uint n)
        {
            var b = new byte[4];
            Wire.WriteUInt32LittleEndian(b, 0, n); stream.Write(b);
        }
        internal void String(string s) { WriteUInt32((uint)s.Length + 1); WriteUInt32(0); WriteUInt32((uint)s.Length + 1); stream.Write(Encoding.Unicode.GetBytes(s + "\0")); while ((stream.Position & 3) != 0) stream.WriteByte(0); }
        internal byte[] Bytes() => stream.ToArray();
    }
}
