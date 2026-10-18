namespace Tedd.SMB3;

// Native API layouts are deliberately distinct from SMB/MS-FSCC information classes.
// statx is read without following the final component; it is not an SMB wire structure.
internal static class LinuxStatx
{
    internal const int Size = 256;
    internal const int AtFdcwd = -100;
    internal const int AtSymlinkNoFollow = 0x100;
    internal const int LinkCountOffset = 16;
    internal const int InodeOffset = 32;
    internal const int DeviceIdOffset = 136;
    internal const int DeviceIdSize = 8;
    internal const int ChangeTimeSecondsOffset = 96;
    internal const int ChangeTimeNanosecondsOffset = 104;
    internal const uint BasicStatsMask = 0x7ff;
}

internal static class LinuxError
{
    internal const int Range = 34;
    internal const int NoData = 61;
    internal const int NotSupported = 95;
}

internal static class WindowsFileInfoClass
{
    internal const int FileBasicInfo = 0;
    internal const int FileStandardInfo = 1;
    internal const int FileIdInfo = 18;
}

internal static class WindowsFileFlags
{
    internal const uint BackupSemantics = 0x02000000;
    internal const uint OpenReparsePoint = 0x00200000;
}

internal static class WindowsCreationDisposition
{
    internal const uint OpenExisting = 3;
}

internal static class WindowsFileIdInfo
{
    internal const int Size = 24;
}
