namespace Tedd.Smb;

// Native API layouts are deliberately distinct from SMB/MS-FSCC information classes.
internal static class LinuxStatx
{
    internal const int Size = 256, AtFdcwd = -100, AtSymlinkNoFollow = 0x100,
        LinkCountOffset = 16, InodeOffset = 32, DeviceIdOffset = 136, DeviceIdSize = 8,
        ChangeTimeSecondsOffset = 96, ChangeTimeNanosecondsOffset = 104;
    internal const uint BasicStatsMask = 0x7ff;
}

internal static class LinuxError
{
    internal const int Range = 34, NoData = 61, NotSupported = 95;
}

internal static class WindowsFileInfoClass
{
    internal const int FileBasicInfo = 0, FileStandardInfo = 1, FileIdInfo = 18;
}

internal static class WindowsFileFlags
{
    internal const uint BackupSemantics = 0x02000000, OpenReparsePoint = 0x00200000;
}

internal static class WindowsCreationDisposition
{
    internal const uint OpenExisting = 3;
}

internal static class WindowsFileIdInfo
{
    internal const int Size = 24;
}
