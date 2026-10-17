namespace Tedd.Smb;

// MS-FSCC information buffers. Offsets start at the information buffer, not the SMB2 header.
internal static class FileBasicInformation
{
    internal const int Size = 40, CreationTimeOffset = 0, LastAccessTimeOffset = 8,
        LastWriteTimeOffset = 16, ChangeTimeOffset = 24, FileAttributesOffset = 32, TimestampCount = 4;
}

internal static class FileStandardInformation
{
    internal const int Size = 24, AllocationSizeOffset = 0, EndOfFileOffset = 8,
        NumberOfLinksOffset = 16, DeletePendingOffset = 20, DirectoryOffset = 21;
}

internal static class FileInternalInformation
{
    internal const int Size = sizeof(ulong);
}

internal static class FileDispositionInformation
{
    internal const int Size = sizeof(byte), DeletePendingOffset = 0;
}

internal static class FileEndOfFileInformation
{
    internal const int Size = sizeof(ulong), EndOfFileOffset = 0;
}

internal static class FileNetworkOpenInformation
{
    internal const int Size = 56, AllocationSizeOffset = 32, EndOfFileOffset = 40, FileAttributesOffset = 48;
}

internal static class FileAllInformation
{
    internal const int FixedSize = 100, StandardInformationOffset = 40, IndexNumberOffset = 64,
        AccessFlagsOffset = 76, FileNameLengthOffset = 96, FileNameOffset = 100;
}

internal static class FileDirectoryInformation
{
    internal const int FixedSize = 64, FullFixedSize = 68, BothFixedSize = 94,
        IdBothFixedSize = 104, IdFullFixedSize = 80, NamesFixedSize = 12,
        NextEntryOffsetFieldOffset = 0, FileIndexOffset = 4, CreationTimeOffset = 8,
        LastWriteTimeOffset = 24, EndOfFileOffset = 40, AllocationSizeOffset = 48,
        FileAttributesOffset = 56, FileNameLengthOffset = 60, NamesFileNameLengthOffset = 8,
        IdBothFileIdOffset = 96, IdFullFileIdOffset = 72;
}

internal static class FileRenameInformation
{
    internal const int FixedSize = 20, ReplaceIfExistsOffset = 0, RootDirectoryOffset = 8, FileNameLengthOffset = 16;
}

internal static class FileStreamInformation
{
    internal const int FixedSize = 24, StreamNameLengthOffset = 4, StreamSizeOffset = 8, StreamAllocationSizeOffset = 16;
}

internal static class FileAttributeTagInformation
{
    internal const int Size = 8, FileAttributesOffset = 0;
}

internal static class FileCompressionInformation
{
    internal const int Size = 16, CompressedFileSizeOffset = 0;
}

internal static class FileFsVolumeInformation
{
    internal const int FixedSize = 18, VolumeCreationTimeOffset = 0, VolumeSerialNumberOffset = 8, VolumeLabelLengthOffset = 12;
}

internal static class FileFsSizeInformation
{
    internal const int Size = 24, TotalAllocationUnitsOffset = 0, AvailableAllocationUnitsOffset = 8,
        SectorsPerAllocationUnitOffset = 16, BytesPerSectorOffset = 20;
}

internal static class FileFsFullSizeInformation
{
    internal const int Size = 32, ActualAvailableAllocationUnitsOffset = 16,
        SectorsPerAllocationUnitOffset = 24, BytesPerSectorOffset = 28;
}

internal static class FileFsDeviceInformation
{
    internal const int Size = 8, DeviceTypeOffset = 0, CharacteristicsOffset = 4;
    internal const uint FileDeviceDisk = 0x00000007, FileRemoteDevice = 0x00000010;
}

internal static class FileFsAttributeInformation
{
    internal const int FixedSize = 12, FileSystemAttributesOffset = 0, MaximumComponentNameLengthOffset = 4, FileSystemNameLengthOffset = 8;
}

internal static class FileFsControlInformation
{
    internal const int Size = 48;
}

internal static class FileFsSectorSizeInformation
{
    internal const int Size = 28, LogicalBytesPerSectorOffset = 0, PhysicalBytesPerSectorForAtomicityOffset = 4,
        PhysicalBytesPerSectorForPerformanceOffset = 8, FileSystemEffectivePhysicalBytesPerSectorForAtomicityOffset = 12,
        FlagsOffset = 16;
    internal const uint AlignedDevice = 0x00000001, PartitionAlignedOnDevice = 0x00000002;
}

internal static class Smb2FileId
{
    internal const int Size = 16;
    internal const byte RelatedOperationByte = 0xff;
}
