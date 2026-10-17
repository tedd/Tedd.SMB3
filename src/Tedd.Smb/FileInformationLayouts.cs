namespace Tedd.Smb;

// MS-FSCC information buffers. Offsets start at the information buffer, not the SMB3 packet header.
internal static class FileBasicInformation
{
    internal const int Size = 40;
    internal const int CreationTimeOffset = 0;
    internal const int LastAccessTimeOffset = 8;
    internal const int LastWriteTimeOffset = 16;
    internal const int ChangeTimeOffset = 24;
    internal const int FileAttributesOffset = 32;
    internal const int TimestampCount = 4;
}

internal static class FileStandardInformation
{
    internal const int Size = 24;
    internal const int AllocationSizeOffset = 0;
    internal const int EndOfFileOffset = 8;
    internal const int NumberOfLinksOffset = 16;
    internal const int DeletePendingOffset = 20;
    internal const int DirectoryOffset = 21;
}

internal static class FileInternalInformation
{
    internal const int Size = sizeof(ulong);
}

internal static class FileDispositionInformation
{
    internal const int Size = sizeof(byte);
    internal const int DeletePendingOffset = 0;
}

internal static class FileEndOfFileInformation
{
    internal const int Size = sizeof(ulong);
    internal const int EndOfFileOffset = 0;
}

internal static class FileNetworkOpenInformation
{
    internal const int Size = 56;
    internal const int AllocationSizeOffset = 32;
    internal const int EndOfFileOffset = 40;
    internal const int FileAttributesOffset = 48;
}

internal static class FileAllInformation
{
    internal const int FixedSize = 100;
    internal const int StandardInformationOffset = 40;
    internal const int IndexNumberOffset = 64;
    internal const int AccessFlagsOffset = 76;
    internal const int FileNameLengthOffset = 96;
    internal const int FileNameOffset = 100;
}

// Each directory entry may be padded; NextEntryOffset, not name length, advances the chain.
internal static class FileDirectoryInformation
{
    internal const int FixedSize = 64;
    internal const int FullFixedSize = 68;
    internal const int BothFixedSize = 94;
    internal const int IdBothFixedSize = 104;
    internal const int IdFullFixedSize = 80;
    internal const int NamesFixedSize = 12;
    internal const int NextEntryOffsetFieldOffset = 0;
    internal const int FileIndexOffset = 4;
    internal const int CreationTimeOffset = 8;
    internal const int LastWriteTimeOffset = 24;
    internal const int EndOfFileOffset = 40;
    internal const int AllocationSizeOffset = 48;
    internal const int FileAttributesOffset = 56;
    internal const int FileNameLengthOffset = 60;
    internal const int NamesFileNameLengthOffset = 8;
    internal const int IdBothFileIdOffset = 96;
    internal const int IdFullFileIdOffset = 72;
}

internal static class FileRenameInformation
{
    internal const int FixedSize = 20;
    internal const int ReplaceIfExistsOffset = 0;
    internal const int RootDirectoryOffset = 8;
    internal const int FileNameLengthOffset = 16;
}

internal static class FileStreamInformation
{
    internal const int FixedSize = 24;
    internal const int StreamNameLengthOffset = 4;
    internal const int StreamSizeOffset = 8;
    internal const int StreamAllocationSizeOffset = 16;
}

internal static class FileAttributeTagInformation
{
    internal const int Size = 8;
    internal const int FileAttributesOffset = 0;
}

internal static class FileCompressionInformation
{
    internal const int Size = 16;
    internal const int CompressedFileSizeOffset = 0;
}

internal static class FileFsVolumeInformation
{
    internal const int FixedSize = 18;
    internal const int VolumeCreationTimeOffset = 0;
    internal const int VolumeSerialNumberOffset = 8;
    internal const int VolumeLabelLengthOffset = 12;
}

internal static class FileFsSizeInformation
{
    internal const int Size = 24;
    internal const int TotalAllocationUnitsOffset = 0;
    internal const int AvailableAllocationUnitsOffset = 8;
    internal const int SectorsPerAllocationUnitOffset = 16;
    internal const int BytesPerSectorOffset = 20;
}

internal static class FileFsFullSizeInformation
{
    internal const int Size = 32;
    internal const int ActualAvailableAllocationUnitsOffset = 16;
    internal const int SectorsPerAllocationUnitOffset = 24;
    internal const int BytesPerSectorOffset = 28;
}

internal static class FileFsDeviceInformation
{
    internal const int Size = 8;
    internal const int DeviceTypeOffset = 0;
    internal const int CharacteristicsOffset = 4;
    internal const uint FileDeviceDisk = 0x00000007;
    internal const uint FileRemoteDevice = 0x00000010;
}

internal static class FileFsAttributeInformation
{
    internal const int FixedSize = 12;
    internal const int FileSystemAttributesOffset = 0;
    internal const int MaximumComponentNameLengthOffset = 4;
    internal const int FileSystemNameLengthOffset = 8;
}

internal static class FileFsControlInformation
{
    internal const int Size = 48;
}

internal static class FileFsSectorSizeInformation
{
    internal const int Size = 28;
    internal const int LogicalBytesPerSectorOffset = 0;
    internal const int PhysicalBytesPerSectorForAtomicityOffset = 4;
    internal const int PhysicalBytesPerSectorForPerformanceOffset = 8;
    internal const int FileSystemEffectivePhysicalBytesPerSectorForAtomicityOffset = 12;
    internal const int FlagsOffset = 16;
    internal const uint AlignedDevice = 0x00000001;
    internal const uint PartitionAlignedOnDevice = 0x00000002;
}

internal static class Smb3FileId
{
    internal const int Size = 16;
    internal const byte RelatedOperationByte = 0xff;
}
