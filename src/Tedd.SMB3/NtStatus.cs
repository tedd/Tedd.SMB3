namespace Tedd.SMB3;

// MS-ERREF NTSTATUS names, without the STATUS_ prefix.
internal static class NtStatus
{
    internal const uint Success = 0x00000000;
    internal const uint BufferOverflow = 0x80000005;
    internal const uint NoMoreFiles = 0x80000006;
    internal const uint InvalidInfoClass = 0xc0000003;
    internal const uint InfoLengthMismatch = 0xc0000004;
    internal const uint InvalidHandle = 0xc0000008;
    internal const uint InvalidParameter = 0xc000000d;
    internal const uint EndOfFile = 0xc0000011;
    // SESSION_SETUP uses this status to continue authentication rather than fail it.
    internal const uint MoreProcessingRequired = 0xc0000016;
    internal const uint AccessDenied = 0xc0000022;
    internal const uint BufferTooSmall = 0xc0000023;
    internal const uint ObjectNameNotFound = 0xc0000034;
    internal const uint ObjectNameCollision = 0xc0000035;
    internal const uint SharingViolation = 0xc0000043;
    internal const uint EasNotSupported = 0xc000004f;
    internal const uint DeletePending = 0xc0000056;
    internal const uint LogonFailure = 0xc000006d;
    internal const uint PipeBusy = 0xc00000ae;
    internal const uint PipeDisconnected = 0xc00000b0;
    internal const uint FileIsADirectory = 0xc00000ba;
    internal const uint NotSupported = 0xc00000bb;
    internal const uint NetworkNameDeleted = 0xc00000c9;
    internal const uint BadNetworkName = 0xc00000cc;
    internal const uint DirectoryNotEmpty = 0xc0000101;
    internal const uint NotADirectory = 0xc0000103;
    internal const uint TooManyOpenedFiles = 0xc000011f;
    internal const uint UserSessionDeleted = 0xc0000203;
    internal const uint NotFound = 0xc0000225;
}
