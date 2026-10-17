namespace Tedd.Smb;

// MS-SMB2 wire values. These remain constants rather than enums so the existing
// integer serializers and flag expressions retain their exact underlying types.
internal static class Smb2Command
{
    internal const ushort Negotiate = 0x0000, SessionSetup = 0x0001, Logoff = 0x0002,
        TreeConnect = 0x0003, TreeDisconnect = 0x0004, Create = 0x0005, Close = 0x0006,
        Flush = 0x0007, Read = 0x0008, Write = 0x0009, Ioctl = 0x000b, Cancel = 0x000c,
        Echo = 0x000d, QueryDirectory = 0x000e, QueryInfo = 0x0010, SetInfo = 0x0011;
}

internal static class Smb2Dialect
{
    internal const ushort Wildcard = 0x02ff, Smb311 = 0x0311;
}

internal static class Smb2HeaderFlags
{
    internal const uint ServerToRedir = 0x00000001, AsyncCommand = 0x00000002,
        RelatedOperations = 0x00000004, Signed = 0x00000008;
    internal const uint ResponseOrAsync = ServerToRedir | AsyncCommand;
}

internal static class Smb2SecurityMode
{
    internal const ushort SigningEnabled = 0x0001, SigningRequired = 0x0002;
    internal const ushort SigningEnabledAndRequired = SigningEnabled | SigningRequired;
}

internal static class Smb2GlobalCapabilities
{
    internal const uint Encryption = 0x00000040;
}

internal static class Smb2SessionFlags
{
    internal const ushort IsGuest = 0x0001, IsNull = 0x0002, EncryptData = 0x0004;
}

internal static class Smb2ShareType
{
    internal const byte Disk = 0x01, Pipe = 0x02;
}

internal static class Smb2ShareFlags
{
    internal const uint NoCaching = 0x00000030, EncryptData = 0x00008000;
}

internal static class Smb2NegotiateContextType
{
    internal const ushort PreauthIntegrityCapabilities = 0x0001, EncryptionCapabilities = 0x0002,
        SigningCapabilities = 0x0008;
}

internal static class Smb2PreauthHashAlgorithm
{
    internal const ushort Sha512 = 0x0001;
}

internal static class Smb2Cipher
{
    internal const ushort None = 0, Aes128Ccm = 0x0001, Aes128Gcm = 0x0002;
}

internal static class Smb2SigningAlgorithm
{
    internal const ushort AesCmac = 0x0001;
}

internal static class Smb2ImpersonationLevel
{
    internal const uint Impersonation = 0x00000002;
}

internal static class Smb2CreateDisposition
{
    internal const uint Supersede = 0, Open = 1, Create = 2, OpenIf = 3, Overwrite = 4, OverwriteIf = 5;
}

internal static class Smb2CreateAction
{
    internal const uint Superseded = 0, Opened = 1, Created = 2, Overwritten = 3;
}

internal static class Smb2CreateOptions
{
    internal const uint DirectoryFile = 0x00000001, WriteThrough = 0x00000002,
        NonDirectoryFile = 0x00000040, DeleteOnClose = 0x00001000, OpenByFileId = 0x00002000;
    internal const uint ConflictingDirectoryOptions = DirectoryFile | NonDirectoryFile;
}

internal static class FileAccessMask
{
    internal const uint ReadData = 0x00000001, WriteData = 0x00000002, AppendData = 0x00000004,
        ReadEa = 0x00000008, WriteEa = 0x00000010, Execute = 0x00000020,
        ReadAttributes = 0x00000080, WriteAttributes = 0x00000100,
        Delete = 0x00010000, ReadControl = 0x00020000, WriteDac = 0x00040000,
        WriteOwner = 0x00080000, Synchronize = 0x00100000, AccessSystemSecurity = 0x01000000,
        MaximumAllowed = 0x02000000, GenericAll = 0x10000000, GenericExecute = 0x20000000,
        GenericWrite = 0x40000000, GenericRead = 0x80000000;
    internal const uint FileGenericRead = ReadControl | ReadData | ReadAttributes | ReadEa | Synchronize;
    internal const uint FileGenericWrite = ReadControl | WriteData | AppendData | WriteAttributes | WriteEa | Synchronize;
    internal const uint FileGenericExecute = ReadControl | ReadAttributes | Execute | Synchronize;
    internal const uint FileAllAccess = 0x001f01ff;
}

internal static class FileShareAccess
{
    internal const uint Read = 0x00000001, Write = 0x00000002, Delete = 0x00000004;
    internal const uint All = Read | Write | Delete;
}

internal static class Smb2QueryDirectoryFlags
{
    internal const byte RestartScans = 0x01, ReturnSingleEntry = 0x02, Reopen = 0x10;
}

internal static class Smb2CloseFlags
{
    internal const ushort PostqueryAttributes = 0x0001;
}

internal static class Smb2WriteFlags
{
    internal const uint WriteThrough = 0x00000001;
}

internal static class Smb2InfoType
{
    internal const byte File = 0x01, FileSystem = 0x02;
}

internal static class FileInformationClass
{
    internal const byte DirectoryInformation = 1, FullDirectoryInformation = 2, BothDirectoryInformation = 3,
        BasicInformation = 4, StandardInformation = 5, InternalInformation = 6, EaInformation = 7,
        AccessInformation = 8, RenameInformation = 10, NamesInformation = 12, DispositionInformation = 13,
        PositionInformation = 14, ModeInformation = 16, AlignmentInformation = 17, AllInformation = 18,
        AllocationInformation = 19, EndOfFileInformation = 20, StreamInformation = 22,
        CompressionInformation = 28, NetworkOpenInformation = 34, AttributeTagInformation = 35,
        IdBothDirectoryInformation = 37, IdFullDirectoryInformation = 38;
}

internal static class FileSystemInformationClass
{
    internal const byte VolumeInformation = 1, SizeInformation = 3, DeviceInformation = 4,
        AttributeInformation = 5, ControlInformation = 6, FullSizeInformation = 7, SectorSizeInformation = 11;
}

internal static class FileSystemControlCode
{
    internal const uint PipeTransceive = 0x0011c017, ValidateNegotiateInfo = 0x00140204;
}

internal static class Smb2CreateContextName
{
    internal const string EaBuffer = "ExtA", TimewarpToken = "TWrp", QueryMaximalAccess = "MxAc", QueryOnDiskId = "QFid";
}

internal static class FileAttributeFlags
{
    internal const uint ReadOnly = 0x00000001, Hidden = 0x00000002, System = 0x00000004,
        Directory = 0x00000010, Archive = 0x00000020, Normal = 0x00000080;
}

internal static class FileSystemAttributeFlags
{
    internal const uint CasePreservedNames = 0x00000002, UnicodeOnDisk = 0x00000004, ReadOnlyVolume = 0x00080000;
}

// Implementation policy, separate from protocol-defined values and structures.
internal static class SmbLimits
{
    internal const int DefaultPort = 445, MaxTransferSize = 65536, MaxFrameSize = 4 * 1024 * 1024,
        MaxCredits = 32, MaxCompoundCommands = 32, DefaultMaxConnections = 32,
        MaxConnections = 1024, MaxTrees = 64, MaxHandles = 1024, MaxCreateContexts = 16,
        MaxNegotiateContexts = 32, MaxAuthenticationTokenSize = 16384, MaxComponentLength = 255,
        AllocationUnitSize = 4096, SectorSize = 512, PreauthSaltSize = 32, InitialInformationBufferSize = 512;
    internal const uint VolumeSerialNumber = 0x534d4233;
    internal const uint DefaultProcessId = 0x0000feff;
    internal const string FileSystemName = "SMB3";
    internal const uint ReadAccess = FileAccessMask.FileGenericRead | FileAccessMask.Execute;
    internal const uint SupportedFileAccess = 0x001301ff;
    internal const uint ReadSharingAccess = FileAccessMask.ReadData | FileAccessMask.Execute;
    internal const uint WriteSharingAccess = FileAccessMask.WriteData | FileAccessMask.AppendData;
    internal const uint UnsupportedSecurityAccess = FileAccessMask.AccessSystemSecurity | FileAccessMask.WriteDac | FileAccessMask.WriteOwner;
    internal const uint MutatingAccess = FileAccessMask.WriteData | FileAccessMask.AppendData | FileAccessMask.WriteEa |
        FileAccessMask.WriteAttributes | FileAccessMask.Delete | FileAccessMask.WriteDac | FileAccessMask.WriteOwner;
    internal const uint SupportedFileAttributes = FileAttributeFlags.ReadOnly | FileAttributeFlags.Hidden |
        FileAttributeFlags.Directory | FileAttributeFlags.Archive | FileAttributeFlags.Normal;
}
