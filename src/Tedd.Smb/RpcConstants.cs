namespace Tedd.Smb;

// MS-RPCE connection-oriented PDUs and MS-SRVS operation numbers.
internal static class RpcPacketType
{
    internal const byte Request = 0, Response = 2, Fault = 3, Bind = 11, BindAck = 12;
}

internal static class RpcPacketFlags
{
    internal const byte FirstFragment = 0x01, LastFragment = 0x02, PendingCancel = 0x04, ConcurrentMultiplexing = 0x10;
    internal const byte CompleteFragment = FirstFragment | LastFragment;
    internal const byte Supported = CompleteFragment | PendingCancel | ConcurrentMultiplexing;
}

internal static class RpcHeader
{
    internal const int Size = 16, VersionOffset = 0, VersionMinorOffset = 1, PacketTypeOffset = 2,
        FlagsOffset = 3, DataRepresentationOffset = 4, FragmentLengthOffset = 8,
        AuthLengthOffset = 10, CallIdOffset = 12;
    internal const byte Version = 5, LittleEndianDataRepresentation = 0x10;
}

internal static class RpcRequest
{
    internal const int HeaderSize = 24, AllocationHintOffset = 16, ContextIdOffset = 20, OpnumOffset = 22;
}

internal static class RpcResponse
{
    internal const int HeaderSize = 24, AllocationHintOffset = 16, ContextIdOffset = 20;
}

internal static class RpcBind
{
    internal const int FixedSize = 28, ContextCountOffset = 24, ContextElementFixedSize = 24,
        ContextIdOffset = 0, TransferSyntaxCountOffset = 2, AbstractSyntaxOffset = 4;
}

internal static class RpcBindAck
{
    internal const int FixedSize = 26, MaxTransmitFragmentOffset = 16, MaxReceiveFragmentOffset = 18,
        AssociationGroupIdOffset = 20, SecondaryAddressLengthOffset = 24, ResultListHeaderSize = 4,
        ResultSize = 24, ResultOffset = 0, ReasonOffset = 2, TransferSyntaxOffset = 4;
    internal const ushort ProviderRejection = 2, ProposedTransferSyntaxesNotSupported = 2;
}

internal static class RpcFault
{
    internal const int Size = 32, ContextIdOffset = 20, StatusOffset = 24;
    internal const uint ContextMismatch = 0x1c00001a, OperationRangeError = 0x1c010002;
}

internal static class RpcSyntaxIdentifier
{
    internal const int Size = 20;
}

internal static class SrvsvcOpnum
{
    internal const ushort NetrShareEnum = 15, NetrShareGetInfo = 16;
}

internal static class SrvsvcShareInfoLevel
{
    internal const uint Name = 0, Remark = 1, Path = 2, Flags = 1005;
}

internal static class SrvsvcShareType
{
    internal const uint DiskTree = 0x00000000, Ipc = 0x00000003, Special = 0x80000000;
}

internal static class Win32Error
{
    internal const uint Success = 0, InvalidLevel = 124, MoreData = 234, NetNameNotFound = 2310;
}

internal static class RpcLimits
{
    internal const int MaxBufferedBytes = 65536, MaxFragmentSize = ushort.MaxValue, MaxContexts = 8,
        MaxTransferSyntaxes = 8, MaxStringCharacters = 1024, ShareCount = 2;
}

// Nonzero NDR32 referent identifiers are chosen by this implementation, not fixed by MS-SRVS.
internal static class SrvsvcReferent
{
    internal const uint Container = 0x10000, Buffer = 0x10004, ResumeHandle = 0x10008,
        ShareName = 0x20000, ShareRemark = 0x20004, SharePath = 0x20008;
    internal const int ShareStride = 16;
}
