namespace Tedd.SMB3;

// MS-RPCE connection-oriented PDUs and MS-SRVS operation numbers.
internal static class RpcPacketType
{
    internal const byte Request = 0;
    internal const byte Response = 2;
    internal const byte Fault = 3;
    internal const byte Bind = 11;
    internal const byte BindAck = 12;
}

internal static class RpcPacketFlags
{
    internal const byte FirstFragment = 0x01;
    internal const byte LastFragment = 0x02;
    internal const byte PendingCancel = 0x04;
    internal const byte ConcurrentMultiplexing = 0x10;
    internal const byte CompleteFragment = FirstFragment | LastFragment;
    internal const byte Supported = CompleteFragment | PendingCancel | ConcurrentMultiplexing;
}

// FragmentLength bounds the entire PDU, including this common header.
internal static class RpcHeader
{
    internal const int Size = 16;
    internal const int VersionOffset = 0;
    internal const int VersionMinorOffset = 1;
    internal const int PacketTypeOffset = 2;
    internal const int FlagsOffset = 3;
    internal const int DataRepresentationOffset = 4;
    internal const int FragmentLengthOffset = 8;
    internal const int AuthLengthOffset = 10;
    internal const int CallIdOffset = 12;
    internal const byte Version = 5;
    internal const byte LittleEndianDataRepresentation = 0x10;
}

internal static class RpcRequest
{
    internal const int HeaderSize = 24;
    internal const int AllocationHintOffset = 16;
    internal const int ContextIdOffset = 20;
    internal const int OpnumOffset = 22;
}

internal static class RpcResponse
{
    internal const int HeaderSize = 24;
    internal const int AllocationHintOffset = 16;
    internal const int ContextIdOffset = 20;
}

internal static class RpcBind
{
    internal const int FixedSize = 28;
    internal const int ContextCountOffset = 24;
    internal const int ContextElementFixedSize = 24;
    internal const int ContextIdOffset = 0;
    internal const int TransferSyntaxCountOffset = 2;
    internal const int AbstractSyntaxOffset = 4;
}

internal static class RpcBindAck
{
    internal const int FixedSize = 26;
    internal const int MaxTransmitFragmentOffset = 16;
    internal const int MaxReceiveFragmentOffset = 18;
    internal const int AssociationGroupIdOffset = 20;
    internal const int SecondaryAddressLengthOffset = 24;
    internal const int ResultListHeaderSize = 4;
    internal const int ResultSize = 24;
    internal const int ResultOffset = 0;
    internal const int ReasonOffset = 2;
    internal const int TransferSyntaxOffset = 4;
    internal const ushort ProviderRejection = 2;
    internal const ushort ProposedTransferSyntaxesNotSupported = 2;
}

internal static class RpcFault
{
    internal const int Size = 32;
    internal const int ContextIdOffset = 20;
    internal const int StatusOffset = 24;
    internal const uint ContextMismatch = 0x1c00001a;
    internal const uint OperationRangeError = 0x1c010002;
}

internal static class RpcSyntaxIdentifier
{
    internal const int Size = 20;
}

internal static class SrvsvcOpnum
{
    internal const ushort NetrShareEnum = 15;
    internal const ushort NetrShareGetInfo = 16;
}

internal static class SrvsvcShareInfoLevel
{
    internal const uint Name = 0;
    internal const uint Remark = 1;
    internal const uint Path = 2;
    internal const uint Flags = 1005;
}

internal static class SrvsvcShareType
{
    internal const uint DiskTree = 0x00000000;
    internal const uint Ipc = 0x00000003;
    internal const uint Special = 0x80000000;
}

internal static class Win32Error
{
    internal const uint Success = 0;
    internal const uint InvalidLevel = 124;
    internal const uint MoreData = 234;
    internal const uint NetNameNotFound = 2310;
}

internal static class RpcLimits
{
    internal const int MaxBufferedBytes = 65536;
    internal const int MaxFragmentSize = ushort.MaxValue;
    internal const int MaxContexts = 8;
    internal const int MaxTransferSyntaxes = 8;
    internal const int MaxStringCharacters = 1024;
    internal const int ShareCount = 2;
}

// Nonzero NDR32 referent identifiers are chosen by this implementation, not fixed by MS-SRVS.
internal static class SrvsvcReferent
{
    internal const uint Container = 0x10000;
    internal const uint Buffer = 0x10004;
    internal const uint ResumeHandle = 0x10008;
    internal const uint ShareName = 0x20000;
    internal const uint ShareRemark = 0x20004;
    internal const uint SharePath = 0x20008;
    internal const int ShareStride = 16;
}
