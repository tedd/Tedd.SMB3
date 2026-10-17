namespace Tedd.Smb;

// SMB 3.1.1 retains the SMB2 packet format defined by MS-SMB2.
// Offsets are in bytes; header offsets start at the protocol identifier.
// Request/response offsets start at the command body, excluding the header.
// StructureSize is the wire field value; FixedSize excludes any variable buffer.
internal static class Smb3Header
{
    internal const int Size = 64;
    internal const int ProtocolIdOffset = 0;
    internal const int StructureSizeOffset = 4;
    internal const int CreditChargeOffset = 6;
    internal const int StatusOffset = 8;
    internal const int CommandOffset = 12;
    internal const int CreditsOffset = 14;
    internal const int FlagsOffset = 16;
    internal const int NextCommandOffset = 20;
    internal const int MessageIdOffset = 24;
    internal const int ProcessIdOffset = 32;
    internal const int TreeIdOffset = 36;
    internal const int SessionIdOffset = 40;
    internal const int SignatureOffset = 48;
    internal const int SignatureSize = 16;
    internal const uint ProtocolId = 0x424d53fe;
    internal const byte ProtocolPrefix = 0xfe;
}

// Authentication covers AssociatedData; the signature contains the AEAD tag.
internal static class Smb3TransformHeader
{
    internal const int Size = 52;
    internal const int ProtocolIdOffset = 0;
    internal const int SignatureOffset = 4;
    internal const int SignatureSize = 16;
    internal const int NonceOffset = 20;
    internal const int NonceSize = 16;
    internal const int OriginalMessageSizeOffset = 36;
    internal const int ReservedOffset = 40;
    internal const int FlagsOffset = 42;
    internal const int SessionIdOffset = 44;
    internal const int AssociatedDataOffset = NonceOffset;
    internal const int AssociatedDataSize = Size - AssociatedDataOffset;
    internal const ushort Encrypted = 0x0001;
    internal const uint ProtocolId = 0x424d53fd;
    internal const byte ProtocolPrefix = 0xfd;
}

internal static class Smb1NegotiateEnvelope
{
    internal const int FixedSize = 35;
    internal const int CommandOffset = 4;
    internal const int WordCountOffset = 32;
    internal const int ByteCountOffset = 33;
    internal const uint ProtocolId = 0x424d53ff;
    internal const byte ProtocolPrefix = 0xff;
    internal const byte NegotiateCommand = 0x72;
}

internal static class Smb3NegotiateRequest
{
    internal const int FixedSize = 36;
    internal const int StructureSize = 36;
    internal const int DialectCountOffset = 2;
    internal const int SecurityModeOffset = 4;
    internal const int CapabilitiesOffset = 8;
    internal const int ClientGuidOffset = 12;
    internal const int NegotiateContextOffsetFieldOffset = 28;
    internal const int NegotiateContextCountOffset = 32;
    internal const int DialectsOffset = 36;
}

internal static class Smb3NegotiateResponse
{
    internal const int FixedSize = 64;
    internal const int StructureSize = 65;
    internal const int SecurityModeOffset = 2;
    internal const int DialectRevisionOffset = 4;
    internal const int NegotiateContextCountOffset = 6;
    internal const int ServerGuidOffset = 8;
    internal const int CapabilitiesOffset = 24;
    internal const int MaxTransactSizeOffset = 28;
    internal const int MaxReadSizeOffset = 32;
    internal const int MaxWriteSizeOffset = 36;
    internal const int SystemTimeOffset = 40;
    internal const int SecurityBufferOffsetFieldOffset = 56;
    internal const int SecurityBufferLengthOffset = 58;
    internal const int NegotiateContextOffsetFieldOffset = 60;
}

internal static class Smb3NegotiateContext
{
    internal const int HeaderSize = 8;
    internal const int ContextTypeOffset = 0;
    internal const int DataLengthOffset = 2;
}

internal static class Smb3PreauthIntegrityCapabilities
{
    internal const int HashAlgorithmCountOffset = 0;
    internal const int SaltLengthOffset = 2;
    internal const int HashAlgorithmsOffset = 4;
}

internal static class Smb3AlgorithmCapabilities
{
    internal const int AlgorithmCountOffset = 0;
    internal const int AlgorithmsOffset = 2;
}

internal static class Smb3SessionSetupRequest
{
    internal const int FixedSize = 24;
    internal const int StructureSize = 25;
    internal const int FlagsOffset = 2;
    internal const int SecurityModeOffset = 3;
    internal const int SecurityBufferOffsetFieldOffset = 12;
    internal const int SecurityBufferLengthOffset = 14;
    internal const int PreviousSessionIdOffset = 16;
}

internal static class Smb3SessionSetupResponse
{
    internal const int FixedSize = 8;
    internal const int StructureSize = 9;
    internal const int SessionFlagsOffset = 2;
    internal const int SecurityBufferOffsetFieldOffset = 4;
    internal const int SecurityBufferLengthOffset = 6;
}

internal static class Smb3TreeConnectRequest
{
    internal const int FixedSize = 8;
    internal const int StructureSize = 9;
    internal const int PathOffsetFieldOffset = 4;
    internal const int PathLengthOffset = 6;
}

internal static class Smb3TreeConnectResponse
{
    internal const int FixedSize = 16;
    internal const int StructureSize = 16;
    internal const int ShareTypeOffset = 2;
    internal const int ShareFlagsOffset = 4;
    internal const int MaximalAccessOffset = 12;
}

internal static class Smb3CreateRequest
{
    internal const int FixedSize = 56;
    internal const int StructureSize = 57;
    internal const int ImpersonationLevelOffset = 4;
    internal const int DesiredAccessOffset = 24;
    internal const int FileAttributesOffset = 28;
    internal const int ShareAccessOffset = 32;
    internal const int CreateDispositionOffset = 36;
    internal const int CreateOptionsOffset = 40;
    internal const int NameOffsetFieldOffset = 44;
    internal const int NameLengthOffset = 46;
    internal const int CreateContextsOffsetFieldOffset = 48;
    internal const int CreateContextsLengthOffset = 52;
}

internal static class Smb3CreateResponse
{
    internal const int FixedSize = 88;
    internal const int StructureSize = 89;
    internal const int CreateActionOffset = 4;
    internal const int CreationTimeOffset = 8;
    internal const int EndOfFileOffset = 48;
    internal const int FileIdOffset = 64;
    internal const int CreateContextsOffsetFieldOffset = 80;
    internal const int CreateContextsLengthOffset = 84;
}

// Next is relative to this context; name/data offsets are also context-relative.
internal static class Smb3CreateContext
{
    internal const int HeaderSize = 16;
    internal const int NextOffset = 0;
    internal const int NameOffsetFieldOffset = 4;
    internal const int NameLengthOffset = 6;
    internal const int DataOffsetFieldOffset = 10;
    internal const int DataLengthOffset = 12;
    internal const int ResponseNameOffset = 16;
    internal const int ResponseDataOffset = 24;
    internal const int TagSize = 4;
}

internal static class Smb3QueryMaximalAccessResponse
{
    internal const int Size = 8;
    internal const int MaximalAccessOffset = 4;
}

internal static class Smb3QueryOnDiskIdResponse
{
    internal const int Size = 32;
    internal const int DiskFileIdOffset = 0;
    internal const int VolumeIdOffset = 8;
    internal const int IdentifierSize = 8;
}

internal static class Smb3CloseRequest
{
    internal const int FixedSize = 24;
    internal const int StructureSize = 24;
    internal const int FlagsOffset = 2;
    internal const int FileIdOffset = 8;
}

internal static class Smb3CloseResponse
{
    internal const int FixedSize = 60;
    internal const int StructureSize = 60;
    internal const int FlagsOffset = 2;
    internal const int CreationTimeOffset = 8;
}

internal static class Smb3FlushRequest
{
    internal const int FixedSize = 24;
    internal const int StructureSize = 24;
    internal const int FileIdOffset = 8;
}

internal static class Smb3ReadRequest
{
    internal const int FixedSize = 48;
    internal const int StructureSize = 49;
    internal const int LengthOffset = 4;
    internal const int OffsetFieldOffset = 8;
    internal const int FileIdOffset = 16;
    internal const int MinimumCountOffset = 32;
    internal const int ChannelOffset = 36;
    internal const int ReadChannelInfoLengthOffset = 46;
}

internal static class Smb3ReadResponse
{
    internal const int FixedSize = 16;
    internal const int StructureSize = 17;
    internal const int DataOffsetFieldOffset = 2;
    internal const int DataLengthOffset = 4;
}

internal static class Smb3WriteRequest
{
    internal const int FixedSize = 48;
    internal const int StructureSize = 49;
    internal const int DataOffsetFieldOffset = 2;
    internal const int LengthOffset = 4;
    internal const int OffsetFieldOffset = 8;
    internal const int FileIdOffset = 16;
    internal const int ChannelOffset = 32;
    internal const int WriteChannelInfoLengthOffset = 42;
    internal const int FlagsOffset = 44;
}

internal static class Smb3WriteResponse
{
    internal const int FixedSize = 16;
    internal const int StructureSize = 17;
    internal const int CountOffset = 4;
}

internal static class Smb3IoctlRequest
{
    internal const int FixedSize = 56;
    internal const int StructureSize = 57;
    internal const int CtlCodeOffset = 4;
    internal const int FileIdOffset = 8;
    internal const int InputOffsetFieldOffset = 24;
    internal const int InputCountOffset = 28;
    internal const int MaxOutputResponseOffset = 44;
}

internal static class Smb3IoctlResponse
{
    internal const int FixedSize = 48;
    internal const int StructureSize = 49;
    internal const int CtlCodeOffset = 4;
    internal const int FileIdOffset = 8;
    internal const int OutputOffsetFieldOffset = 32;
    internal const int OutputCountOffset = 36;
}

internal static class Smb3QueryDirectoryRequest
{
    internal const int FixedSize = 32;
    internal const int StructureSize = 33;
    internal const int FileInformationClassOffset = 2;
    internal const int FlagsOffset = 3;
    internal const int FileIdOffset = 8;
    internal const int FileNameOffsetFieldOffset = 24;
    internal const int FileNameLengthOffset = 26;
    internal const int OutputBufferLengthOffset = 28;
}

internal static class Smb3QueryInfoRequest
{
    internal const int FixedSize = 40;
    internal const int StructureSize = 41;
    internal const int InfoTypeOffset = 2;
    internal const int FileInfoClassOffset = 3;
    internal const int OutputBufferLengthOffset = 4;
    internal const int InputBufferOffsetFieldOffset = 8;
    internal const int InputBufferLengthOffset = 12;
    internal const int FileIdOffset = 24;
}

// QUERY_INFO and QUERY_DIRECTORY responses share this buffer descriptor layout.
internal static class Smb3QueryResponse
{
    internal const int FixedSize = 8;
    internal const int StructureSize = 9;
    internal const int OutputBufferOffsetFieldOffset = 2;
    internal const int OutputBufferLengthOffset = 4;
}

internal static class Smb3SetInfoRequest
{
    internal const int FixedSize = 32;
    internal const int StructureSize = 33;
    internal const int InfoTypeOffset = 2;
    internal const int FileInfoClassOffset = 3;
    internal const int BufferLengthOffset = 4;
    internal const int BufferOffsetFieldOffset = 8;
    internal const int FileIdOffset = 16;
}

internal static class Smb3SetInfoResponse
{
    internal const int FixedSize = 2;
    internal const int StructureSize = 2;
}

// LOGOFF/TREE_DISCONNECT/ECHO messages, CANCEL requests and FLUSH responses share this layout.
internal static class Smb3SimpleMessage
{
    internal const int FixedSize = 4;
    internal const int StructureSize = 4;
}

internal static class Smb3ErrorResponse
{
    internal const int MinimumSize = 9;
    internal const int StructureSize = 9;
}

internal static class Smb3Cryptography
{
    internal const int PreauthHashSize = 64;
    internal const int SessionKeySize = 16;
    internal const int AesBlockSize = 16;
    internal const int GcmNonceSize = 12;
    internal const int CcmNonceSize = 11;
    internal const int NonceCounterSize = sizeof(ulong);
    // Exact, case-sensitive SMB 3.1.1 KDF labels (MS-SMB2 3.2.5.3.1).
    // C2S means client-to-server; S2C means server-to-client. Neither names a dialect.
    // Crypto.Kdf appends the protocol-required terminating NUL; these values must not change.
    internal const string SigningKeyLabel = "SMBSigningKey";
    internal const string ServerToClientCipherKeyLabel = "SMBS2CCipherKey";
    internal const string ClientToServerCipherKeyLabel = "SMBC2SCipherKey";
}

// The length following the session-message byte is a 24-bit big-endian integer.
internal static class DirectTcpTransport
{
    internal const int HeaderSize = 4;
    internal const byte SessionMessage = 0x00;
}
