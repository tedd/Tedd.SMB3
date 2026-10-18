using System.Buffers;
using System.Net.Sockets;

namespace Tedd.SMB3;

/// <summary>Direct TCP framing with one reusable receive header per connection.</summary>
/// <remarks>The owner serializes sends and receives and owns the network stream.</remarks>
internal sealed class SmbTransport(NetworkStream stream)
{
    private readonly byte[] receiveHeader = new byte[DirectTcpTransport.HeaderSize];
    internal async ValueTask<byte[]> ReceiveAsync(CancellationToken cancellationToken)
    {
        await stream.ReadExactlyAsync(receiveHeader, cancellationToken).ConfigureAwait(false);
        int length = (receiveHeader[1] << 16) | (receiveHeader[2] << 8) | receiveHeader[3];
        if (receiveHeader[0] != DirectTcpTransport.SessionMessage || length < 16 || length > SmbLimits.MaxFrameSize)
            throw new SmbException(NtStatus.InvalidParameter);
        // The returned array has independent ownership and may outlive this exchange.
        var packet = new byte[length];
        await stream.ReadExactlyAsync(packet, cancellationToken).ConfigureAwait(false);
        return packet;
    }

    internal async ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken)
    {
        if (payload.Length > SmbLimits.MaxFrameSize)
            throw new SmbException(NtStatus.InvalidParameter);
        int length = checked(payload.Length + DirectTcpTransport.HeaderSize);
        byte[] staging = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            // A single write retains coalescing; no rental can escape the awaited send.
            staging[0] = DirectTcpTransport.SessionMessage;
            staging[1] = (byte)(payload.Length >> 16);
            staging[2] = (byte)(payload.Length >> 8);
            staging[3] = (byte)payload.Length;
            payload.Span.CopyTo(staging.AsSpan(DirectTcpTransport.HeaderSize));
            await stream.WriteAsync(staging.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            // Authentication tokens and unencrypted file contents must not reach other renters.
            ArrayPool<byte>.Shared.Return(staging, clearArray: true);
        }
    }
}
