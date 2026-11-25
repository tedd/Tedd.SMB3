namespace Tedd.SMB3;

// One exact-sized bulk packet per serialized stage. The caller owns the result
// until the next call and must overwrite the payload before exposing it.
internal sealed class TransferBuffer
{
    private byte[]? buffer;

    internal static byte[] Allocate(int length, int clearPrefix, TransferBuffer? reuse)
    {
        if (reuse == null || length < SmbLimits.MaxTransferSize || length > SmbLimits.MaxFileIoSize + 4096)
            return new byte[length];
        if (reuse.buffer?.Length != length)
            reuse.buffer = new byte[length];
        else
            reuse.buffer.AsSpan(0, clearPrefix).Clear();
        return reuse.buffer;
    }
}
