namespace Tedd.SMB3;

// SMB 3.1.1 wire values from MS-SMB2, which specifies both SMB2 and SMB3.
// The Smb3 prefix identifies this implementation's supported dialect family.
// Constants preserve the integer serializers' exact underlying types.
internal static class Smb3Command
{
    internal const ushort Negotiate = 0x0000;
    internal const ushort SessionSetup = 0x0001;
    internal const ushort Logoff = 0x0002;
    internal const ushort TreeConnect = 0x0003;
    internal const ushort TreeDisconnect = 0x0004;
    internal const ushort Create = 0x0005;
    internal const ushort Close = 0x0006;
    internal const ushort Flush = 0x0007;
    internal const ushort Read = 0x0008;
    internal const ushort Write = 0x0009;
    internal const ushort Ioctl = 0x000b;
    internal const ushort Cancel = 0x000c;
    internal const ushort Echo = 0x000d;
    internal const ushort QueryDirectory = 0x000e;
    internal const ushort QueryInfo = 0x0010;
    internal const ushort SetInfo = 0x0011;
}

internal static class Smb3Dialect
{
    internal const ushort Wildcard = 0x02ff;
    internal const ushort Smb311 = 0x0311;
}

// Response/async bits are validated independently of the signed/related-operation bits.
internal static class Smb3HeaderFlags
{
    internal const uint ServerToRedir = 0x00000001;
    internal const uint AsyncCommand = 0x00000002;
    internal const uint RelatedOperations = 0x00000004;
    internal const uint Signed = 0x00000008;
    internal const uint ResponseOrAsync = ServerToRedir | AsyncCommand;
}

internal static class Smb3SecurityMode
{
    internal const ushort SigningEnabled = 0x0001;
    internal const ushort SigningRequired = 0x0002;
    internal const ushort SigningEnabledAndRequired = SigningEnabled | SigningRequired;
}

internal static class Smb3GlobalCapabilities
{
    internal const uint Encryption = 0x00000040;
}

internal static class Smb3SessionFlags
{
    internal const ushort IsGuest = 0x0001;
    internal const ushort IsNull = 0x0002;
    internal const ushort EncryptData = 0x0004;
}

internal static class Smb3ShareType
{
    internal const byte Disk = 0x01;
    internal const byte Pipe = 0x02;
}

internal static class Smb3ShareFlags
{
    internal const uint NoCaching = 0x00000030;
    internal const uint EncryptData = 0x00008000;
}

internal static class Smb3NegotiateContextType
{
    internal const ushort PreauthIntegrityCapabilities = 0x0001;
    internal const ushort EncryptionCapabilities = 0x0002;
    internal const ushort CompressionCapabilities = 0x0003;
    internal const ushort SigningCapabilities = 0x0008;
}

internal static class Smb3PreauthHashAlgorithm
{
    internal const ushort Sha512 = 0x0001;
}

internal static class Smb3Cipher
{
    internal const ushort None = 0;
    internal const ushort Aes128Ccm = 0x0001;
    internal const ushort Aes128Gcm = 0x0002;
}

internal static class Smb3SigningAlgorithm
{
    internal const ushort AesCmac = 0x0001;
}

internal static class Smb3ImpersonationLevel
{
    internal const uint Impersonation = 0x00000002;
}

internal static class Smb3CreateDisposition
{
    internal const uint Supersede = 0;
    internal const uint Open = 1;
    internal const uint Create = 2;
    internal const uint OpenIf = 3;
    internal const uint Overwrite = 4;
    internal const uint OverwriteIf = 5;
}

internal static class Smb3CreateAction
{
    internal const uint Superseded = 0;
    internal const uint Opened = 1;
    internal const uint Created = 2;
    internal const uint Overwritten = 3;
}

internal static class Smb3CreateOptions
{
    internal const uint DirectoryFile = 0x00000001;
    internal const uint WriteThrough = 0x00000002;
    internal const uint NonDirectoryFile = 0x00000040;
    internal const uint DeleteOnClose = 0x00001000;
    internal const uint OpenByFileId = 0x00002000;
    internal const uint ConflictingDirectoryOptions = DirectoryFile | NonDirectoryFile;
}

// Access rights and share permissions are different masks; both directions must agree.
internal static class FileAccessMask
{
    internal const uint ReadData = 0x00000001;
    internal const uint WriteData = 0x00000002;
    internal const uint AppendData = 0x00000004;
    internal const uint ReadEa = 0x00000008;
    internal const uint WriteEa = 0x00000010;
    internal const uint Execute = 0x00000020;
    internal const uint ReadAttributes = 0x00000080;
    internal const uint WriteAttributes = 0x00000100;
    internal const uint Delete = 0x00010000;
    internal const uint ReadControl = 0x00020000;
    internal const uint WriteDac = 0x00040000;
    internal const uint WriteOwner = 0x00080000;
    internal const uint Synchronize = 0x00100000;
    internal const uint AccessSystemSecurity = 0x01000000;
    internal const uint MaximumAllowed = 0x02000000;
    internal const uint GenericAll = 0x10000000;
    internal const uint GenericExecute = 0x20000000;
    internal const uint GenericWrite = 0x40000000;
    internal const uint GenericRead = 0x80000000;
    internal const uint FileGenericRead = ReadControl | ReadData | ReadAttributes | ReadEa | Synchronize;
    internal const uint FileGenericWrite = ReadControl | WriteData | AppendData | WriteAttributes | WriteEa | Synchronize;
    internal const uint FileGenericExecute = ReadControl | ReadAttributes | Execute | Synchronize;
    internal const uint FileAllAccess = 0x001f01ff;
}

internal static class FileShareAccess
{
    internal const uint Read = 0x00000001;
    internal const uint Write = 0x00000002;
    internal const uint Delete = 0x00000004;
    internal const uint All = Read | Write | Delete;
}

internal static class Smb3QueryDirectoryFlags
{
    internal const byte RestartScans = 0x01;
    internal const byte ReturnSingleEntry = 0x02;
    internal const byte Reopen = 0x10;
}

internal static class Smb3CloseFlags
{
    internal const ushort PostqueryAttributes = 0x0001;
}

internal static class Smb3WriteFlags
{
    internal const uint WriteThrough = 0x00000001;
}

internal static class Smb3InfoType
{
    internal const byte File = 0x01;
    internal const byte FileSystem = 0x02;
}

// MS-FSCC class numbers are not the similarly named Windows API enumeration.
internal static class FileInformationClass
{
    internal const byte DirectoryInformation = 1;
    internal const byte FullDirectoryInformation = 2;
    internal const byte BothDirectoryInformation = 3;
    internal const byte BasicInformation = 4;
    internal const byte StandardInformation = 5;
    internal const byte InternalInformation = 6;
    internal const byte EaInformation = 7;
    internal const byte AccessInformation = 8;
    internal const byte RenameInformation = 10;
    internal const byte NamesInformation = 12;
    internal const byte DispositionInformation = 13;
    internal const byte PositionInformation = 14;
    internal const byte ModeInformation = 16;
    internal const byte AlignmentInformation = 17;
    internal const byte AllInformation = 18;
    internal const byte AllocationInformation = 19;
    internal const byte EndOfFileInformation = 20;
    internal const byte StreamInformation = 22;
    internal const byte CompressionInformation = 28;
    internal const byte NetworkOpenInformation = 34;
    internal const byte AttributeTagInformation = 35;
    internal const byte IdBothDirectoryInformation = 37;
    internal const byte IdFullDirectoryInformation = 38;
}

internal static class FileSystemInformationClass
{
    internal const byte VolumeInformation = 1;
    internal const byte SizeInformation = 3;
    internal const byte DeviceInformation = 4;
    internal const byte AttributeInformation = 5;
    internal const byte ControlInformation = 6;
    internal const byte FullSizeInformation = 7;
    internal const byte SectorSizeInformation = 11;
}

internal static class FileSystemControlCode
{
    internal const uint PipeTransceive = 0x0011c017;
    internal const uint ValidateNegotiateInfo = 0x00140204;
}

internal static class Smb3CreateContextName
{
    internal const string EaBuffer = "ExtA";
    internal const string TimewarpToken = "TWrp";
    internal const string QueryMaximalAccess = "MxAc";
    internal const string QueryOnDiskId = "QFid";
}

internal static class FileAttributeFlags
{
    internal const uint ReadOnly = 0x00000001;
    internal const uint Hidden = 0x00000002;
    internal const uint System = 0x00000004;
    internal const uint Directory = 0x00000010;
    internal const uint Archive = 0x00000020;
    internal const uint Normal = 0x00000080;
}

internal static class FileSystemAttributeFlags
{
    internal const uint CasePreservedNames = 0x00000002;
    internal const uint UnicodeOnDisk = 0x00000004;
    internal const uint ReadOnlyVolume = 0x00080000;
}

// Implementation policy, separate from protocol-defined values and structures.
internal static class SmbLimits
{
    internal const int DefaultPort = 445;
    internal const int MaxTransferSize = 65536;
    internal const int MaxFrameSize = 4 * 1024 * 1024;
    internal const int MaxCredits = 32;
    internal const int MaxCompoundCommands = 32;
    internal const int DefaultMaxConnections = 32;
    internal const int MaxConnections = 1024;
    internal const int MaxTrees = 64;
    internal const int MaxHandles = 1024;
    internal const int MaxCreateContexts = 16;
    internal const int MaxNegotiateContexts = 32;
    internal const int MaxAuthenticationTokenSize = 16384;
    internal const int MaxComponentLength = 255;
    internal const int AllocationUnitSize = 4096;
    internal const int SectorSize = 512;
    internal const int PreauthSaltSize = 32;
    internal const int InitialInformationBufferSize = 512;
    internal const uint VolumeSerialNumber = 0x534d4233;
    internal const uint DefaultProcessId = 0x0000feff;
    internal const string FileSystemName = "SMB3";
    internal const uint ReadAccess = FileAccessMask.FileGenericRead | FileAccessMask.Execute;
    internal const uint SupportedFileAccess = 0x001301ff;
    internal const uint ReadSharingAccess = FileAccessMask.ReadData | FileAccessMask.Execute;
    internal const uint WriteSharingAccess = FileAccessMask.WriteData | FileAccessMask.AppendData;
    internal const uint UnsupportedSecurityAccess = FileAccessMask.AccessSystemSecurity | FileAccessMask.WriteDac | FileAccessMask.WriteOwner;
    internal const uint MutatingAccess = FileAccessMask.WriteData | FileAccessMask.AppendData | FileAccessMask.WriteEa | FileAccessMask.WriteAttributes | FileAccessMask.Delete | FileAccessMask.WriteDac | FileAccessMask.WriteOwner;
    internal const uint SupportedFileAttributes = FileAttributeFlags.ReadOnly | FileAttributeFlags.Hidden | FileAttributeFlags.Directory | FileAttributeFlags.Archive | FileAttributeFlags.Normal;
}
