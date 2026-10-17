namespace Tedd.Smb;

// MS-SMB2 offsets, in bytes. Header offsets start at the SMB2 protocol identifier.
// Request/response offsets start at the command body, excluding the SMB2 header.
// StructureSize is the wire field value; FixedSize excludes any variable buffer.
internal static class Smb2Header
{
    internal const int Size = 64, ProtocolIdOffset = 0, StructureSizeOffset = 4, CreditChargeOffset = 6,
        StatusOffset = 8, CommandOffset = 12, CreditsOffset = 14, FlagsOffset = 16,
        NextCommandOffset = 20, MessageIdOffset = 24, ProcessIdOffset = 32,
        TreeIdOffset = 36, SessionIdOffset = 40, SignatureOffset = 48, SignatureSize = 16;
    internal const uint ProtocolId = 0x424d53fe;
    internal const byte ProtocolPrefix = 0xfe;
}

internal static class Smb2TransformHeader
{
    internal const int Size = 52, ProtocolIdOffset = 0, SignatureOffset = 4, SignatureSize = 16,
        NonceOffset = 20, NonceSize = 16, OriginalMessageSizeOffset = 36,
        ReservedOffset = 40, FlagsOffset = 42, SessionIdOffset = 44,
        AssociatedDataOffset = NonceOffset, AssociatedDataSize = Size - AssociatedDataOffset;
    internal const ushort Encrypted = 0x0001;
    internal const uint ProtocolId = 0x424d53fd;
    internal const byte ProtocolPrefix = 0xfd;
}

internal static class Smb1NegotiateEnvelope
{
    internal const int FixedSize = 35, CommandOffset = 4, WordCountOffset = 32, ByteCountOffset = 33;
    internal const uint ProtocolId = 0x424d53ff;
    internal const byte ProtocolPrefix = 0xff, NegotiateCommand = 0x72;
}

internal static class Smb2NegotiateRequest
{
    internal const int FixedSize = 36, StructureSize = 36, DialectCountOffset = 2, SecurityModeOffset = 4,
        CapabilitiesOffset = 8, ClientGuidOffset = 12, NegotiateContextOffsetFieldOffset = 28,
        NegotiateContextCountOffset = 32, DialectsOffset = 36;
}

internal static class Smb2NegotiateResponse
{
    internal const int FixedSize = 64, StructureSize = 65, SecurityModeOffset = 2, DialectRevisionOffset = 4,
        NegotiateContextCountOffset = 6, ServerGuidOffset = 8, CapabilitiesOffset = 24,
        MaxTransactSizeOffset = 28, MaxReadSizeOffset = 32, MaxWriteSizeOffset = 36,
        SystemTimeOffset = 40, SecurityBufferOffsetFieldOffset = 56, SecurityBufferLengthOffset = 58,
        NegotiateContextOffsetFieldOffset = 60;
}

internal static class Smb2NegotiateContext
{
    internal const int HeaderSize = 8, ContextTypeOffset = 0, DataLengthOffset = 2;
}

internal static class Smb2PreauthIntegrityCapabilities
{
    internal const int HashAlgorithmCountOffset = 0, SaltLengthOffset = 2, HashAlgorithmsOffset = 4;
}

internal static class Smb2AlgorithmCapabilities
{
    internal const int AlgorithmCountOffset = 0, AlgorithmsOffset = 2;
}

internal static class Smb2SessionSetupRequest
{
    internal const int FixedSize = 24, StructureSize = 25, FlagsOffset = 2, SecurityModeOffset = 3,
        SecurityBufferOffsetFieldOffset = 12, SecurityBufferLengthOffset = 14, PreviousSessionIdOffset = 16;
}

internal static class Smb2SessionSetupResponse
{
    internal const int FixedSize = 8, StructureSize = 9, SessionFlagsOffset = 2,
        SecurityBufferOffsetFieldOffset = 4, SecurityBufferLengthOffset = 6;
}

internal static class Smb2TreeConnectRequest
{
    internal const int FixedSize = 8, StructureSize = 9, PathOffsetFieldOffset = 4, PathLengthOffset = 6;
}

internal static class Smb2TreeConnectResponse
{
    internal const int FixedSize = 16, StructureSize = 16, ShareTypeOffset = 2, ShareFlagsOffset = 4,
        MaximalAccessOffset = 12;
}

internal static class Smb2CreateRequest
{
    internal const int FixedSize = 56, StructureSize = 57, ImpersonationLevelOffset = 4,
        DesiredAccessOffset = 24, FileAttributesOffset = 28, ShareAccessOffset = 32,
        CreateDispositionOffset = 36, CreateOptionsOffset = 40, NameOffsetFieldOffset = 44,
        NameLengthOffset = 46, CreateContextsOffsetFieldOffset = 48, CreateContextsLengthOffset = 52;
}

internal static class Smb2CreateResponse
{
    internal const int FixedSize = 88, StructureSize = 89, CreateActionOffset = 4,
        CreationTimeOffset = 8, EndOfFileOffset = 48, FileIdOffset = 64,
        CreateContextsOffsetFieldOffset = 80, CreateContextsLengthOffset = 84;
}

internal static class Smb2CreateContext
{
    internal const int HeaderSize = 16, NextOffset = 0, NameOffsetFieldOffset = 4, NameLengthOffset = 6,
        DataOffsetFieldOffset = 10, DataLengthOffset = 12, ResponseNameOffset = 16, ResponseDataOffset = 24;
    internal const int TagSize = 4;
}

internal static class Smb2QueryMaximalAccessResponse
{
    internal const int Size = 8, MaximalAccessOffset = 4;
}

internal static class Smb2QueryOnDiskIdResponse
{
    internal const int Size = 32, DiskFileIdOffset = 0, VolumeIdOffset = 8, IdentifierSize = 8;
}

internal static class Smb2CloseRequest
{
    internal const int FixedSize = 24, StructureSize = 24, FlagsOffset = 2, FileIdOffset = 8;
}

internal static class Smb2CloseResponse
{
    internal const int FixedSize = 60, StructureSize = 60, FlagsOffset = 2, CreationTimeOffset = 8;
}

internal static class Smb2FlushRequest
{
    internal const int FixedSize = 24, StructureSize = 24, FileIdOffset = 8;
}

internal static class Smb2ReadRequest
{
    internal const int FixedSize = 48, StructureSize = 49, LengthOffset = 4, OffsetFieldOffset = 8,
        FileIdOffset = 16, MinimumCountOffset = 32, ChannelOffset = 36, ReadChannelInfoLengthOffset = 46;
}

internal static class Smb2ReadResponse
{
    internal const int FixedSize = 16, StructureSize = 17, DataOffsetFieldOffset = 2, DataLengthOffset = 4;
}

internal static class Smb2WriteRequest
{
    internal const int FixedSize = 48, StructureSize = 49, DataOffsetFieldOffset = 2, LengthOffset = 4,
        OffsetFieldOffset = 8, FileIdOffset = 16, ChannelOffset = 32, WriteChannelInfoLengthOffset = 42, FlagsOffset = 44;
}

internal static class Smb2WriteResponse
{
    internal const int FixedSize = 16, StructureSize = 17, CountOffset = 4;
}

internal static class Smb2IoctlRequest
{
    internal const int FixedSize = 56, StructureSize = 57, CtlCodeOffset = 4, FileIdOffset = 8,
        InputOffsetFieldOffset = 24, InputCountOffset = 28, MaxOutputResponseOffset = 44;
}

internal static class Smb2IoctlResponse
{
    internal const int FixedSize = 48, StructureSize = 49, CtlCodeOffset = 4, FileIdOffset = 8,
        OutputOffsetFieldOffset = 32, OutputCountOffset = 36;
}

internal static class Smb2QueryDirectoryRequest
{
    internal const int FixedSize = 32, StructureSize = 33, FileInformationClassOffset = 2, FlagsOffset = 3,
        FileIdOffset = 8, FileNameOffsetFieldOffset = 24, FileNameLengthOffset = 26, OutputBufferLengthOffset = 28;
}

internal static class Smb2QueryInfoRequest
{
    internal const int FixedSize = 40, StructureSize = 41, InfoTypeOffset = 2, FileInfoClassOffset = 3,
        OutputBufferLengthOffset = 4, InputBufferOffsetFieldOffset = 8, InputBufferLengthOffset = 12, FileIdOffset = 24;
}

// QUERY_INFO and QUERY_DIRECTORY responses share this buffer descriptor layout.
internal static class Smb2QueryResponse
{
    internal const int FixedSize = 8, StructureSize = 9, OutputBufferOffsetFieldOffset = 2, OutputBufferLengthOffset = 4;
}

internal static class Smb2SetInfoRequest
{
    internal const int FixedSize = 32, StructureSize = 33, InfoTypeOffset = 2, FileInfoClassOffset = 3,
        BufferLengthOffset = 4, BufferOffsetFieldOffset = 8, FileIdOffset = 16;
}

internal static class Smb2SetInfoResponse
{
    internal const int FixedSize = 2, StructureSize = 2;
}

// LOGOFF/TREE_DISCONNECT/ECHO messages, CANCEL requests and FLUSH responses share this layout.
internal static class Smb2SimpleMessage
{
    internal const int FixedSize = 4, StructureSize = 4;
}

internal static class Smb2ErrorResponse
{
    internal const int MinimumSize = 9, StructureSize = 9;
}

internal static class Smb3Cryptography
{
    internal const int PreauthHashSize = 64, SessionKeySize = 16, AesBlockSize = 16,
        GcmNonceSize = 12, CcmNonceSize = 11, NonceCounterSize = sizeof(ulong);
    internal const string SigningKeyLabel = "SMBSigningKey", ServerToClientCipherKeyLabel = "SMBS2CCipherKey",
        ClientToServerCipherKeyLabel = "SMBC2SCipherKey";
}

internal static class DirectTcpTransport
{
    internal const int HeaderSize = 4;
    internal const byte SessionMessage = 0x00;
}
