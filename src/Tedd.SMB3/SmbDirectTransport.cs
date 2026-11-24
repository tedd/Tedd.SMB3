using System.Threading.Channels;
using static Tedd.SMB3.Wire;

namespace Tedd.SMB3;

// Each receive completion has already been replaced on the queue before it can earn a new credit.
internal interface IRdmaQueue : IDisposable
{
    int ReceiveDepth { get; }
    // Write this slot before posting. It can be reused once SendAsync completes.
    Memory<byte> SendBuffer { get; }
    // The completed slot remains readable until the next ReceiveAsync call.
    ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct);
    ValueTask SendAsync(int length, CancellationToken ct);
}

/// <summary>MS-SMBD 1.0 in-band transport on a connected, reliable RDMA queue pair.</summary>
internal sealed class SmbDirectTransport : ISmbTransport, IAsyncDisposable
{
    private const int Version = 0x100;
    internal const int DataHeader = 24;
    private readonly IRdmaQueue queue;

    private Span<byte> Outgoing => queue.SendBuffer.Span;
    private readonly SmbDirectReassembly fragments = new();
    private int sendSize, receiveSize, sendLimit, sendCredits, receiveCredits, requested;
    private readonly Channel<byte[]> packets = Channel.CreateBounded<byte[]>(1);
    private readonly SemaphoreSlim sender = new(1);
    private readonly object credits = new();
    private readonly CancellationTokenSource stop = new();
    private TaskCompletionSource? creditWaiter;
    private Task receiver = Task.CompletedTask;
    private Task keepalive = Task.CompletedTask;
    private readonly TimeProvider clock;
    private long lastActivity;
    private long receivedCount;
    private bool replyPending;
    private Exception? failure;

    private SmbDirectTransport(IRdmaQueue queue, TimeProvider clock)
    {
        if (queue.SendBuffer.Length < 128 || queue.ReceiveDepth is < 2 or > ushort.MaxValue)
            throw new ArgumentException("Insufficient RDMA queue capacity.", nameof(queue));
        this.queue = queue;
        this.clock = clock;
        lastActivity = clock.GetTimestamp();
        Outgoing[..32].Clear();
    }

    internal static async ValueTask<SmbDirectTransport> NegotiateAsync(IRdmaQueue queue, bool server, CancellationToken ct, TimeProvider? clock = null)
    {
        var t = new SmbDirectTransport(queue, clock ?? TimeProvider.System);
        using var timer = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timer.CancelAfter(TimeSpan.FromSeconds(5));
        ct = timer.Token;
        if (!server)
        {
            t.WriteVersions();
            WriteUInt16LittleEndian(t.Outgoing, 6, queue.ReceiveDepth);
            t.WriteSizes(8, queue.SendBuffer.Length, queue.SendBuffer.Length);
            await queue.SendAsync(20, ct).ConfigureAwait(false);
        }
        var incoming = await queue.ReceiveAsync(ct).ConfigureAwait(false);
        if (incoming.Length < (server ? 20 : 32)) throw Invalid();
        if (server && (ReadUInt16LittleEndian(incoming.Span, 0) > Version || ReadUInt16LittleEndian(incoming.Span, 2) < Version))
        {
            t.WriteVersions();
            WriteUInt32LittleEndian(t.Outgoing, 12, NtStatus.NotSupported);
            await queue.SendAsync(32, ct).ConfigureAwait(false);
            throw new SmbException(NtStatus.NotSupported);
        }
        int sizes = server ? 8 : 20;
        uint preferred = ReadUInt32LittleEndian(incoming.Span, sizes);
        uint maxReceive = ReadUInt32LittleEndian(incoming.Span, sizes + 4);
        uint maxFragmented = ReadUInt32LittleEndian(incoming.Span, sizes + 8);
        if (!server)
        {
            uint status = ReadUInt32LittleEndian(incoming.Span, 12);
            if (status != 0) throw new SmbException(status);
        }
        t.requested = ReadUInt16LittleEndian(incoming.Span, server ? 6 : 8);
        if (maxReceive < 128 || maxFragmented < 131072 || t.requested == 0) throw Invalid();
        t.sendSize = (int)Math.Min(maxReceive, (uint)queue.SendBuffer.Length);
        t.receiveSize = (int)Math.Clamp(preferred, 128u, (uint)queue.SendBuffer.Length);
        t.sendLimit = (int)Math.Min(maxFragmented, SmbLimits.MaxFrameSize);
        if (server)
        {
            t.WriteVersions();
            WriteUInt16LittleEndian(t.Outgoing, 4, Version);
            WriteUInt16LittleEndian(t.Outgoing, 8, queue.ReceiveDepth);
            t.receiveCredits = Math.Min(queue.ReceiveDepth, t.requested);
            WriteUInt16LittleEndian(t.Outgoing, 10, t.receiveCredits);
            // MaxReadWriteSize is zero. All secured SMB messages travel in-band.
            t.WriteSizes(20, t.sendSize, t.receiveSize);
            await queue.SendAsync(32, ct).ConfigureAwait(false);
        }
        else
        {
            t.sendCredits = ReadUInt16LittleEndian(incoming.Span, 10);
            if (t.sendCredits == 0 || ReadUInt16LittleEndian(incoming.Span, 4) != Version || preferred > queue.SendBuffer.Length)
                throw Invalid();
        }
        t.receiver = t.ReceiveLoopAsync();
        t.keepalive = t.KeepaliveAsync();
        return t;
    }

    private void WriteVersions()
    {
        WriteUInt16LittleEndian(Outgoing, 0, Version);
        WriteUInt16LittleEndian(Outgoing, 2, Version);
    }

    private void WriteSizes(int offset, int send, int receive)
    {
        WriteUInt32LittleEndian(Outgoing, offset, (uint)send);
        WriteUInt32LittleEndian(Outgoing, offset + 4, (uint)receive);
        WriteUInt32LittleEndian(Outgoing, offset + 8, SmbLimits.MaxFrameSize);
    }

    public async ValueTask SendAsync(ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        if (payload.Length == 0 || payload.Length > sendLimit) throw Invalid();
        int messageLength = payload.Length;
        try
        {
            while (!payload.IsEmpty)
            {
                int length = Math.Min(sendSize - DataHeader, payload.Length);
                while (!await TryPostAsync(payload[..length], payload.Length - length, false, ct).ConfigureAwait(false))
                    await WaitForCreditAsync(ct).ConfigureAwait(false);
                payload = payload[length..];
            }
        }
        catch (OperationCanceledException error) when (payload.Length != messageLength)
        {
            // The receiver is waiting for the rest of this message. A later packet
            // cannot start a new message at this point on the same connection.
            await FailAsync(new IOException("SMB Direct fragmented send was interrupted.", error)).ConfigureAwait(false);
            throw;
        }
    }

    private Task WaitForCreditAsync(CancellationToken ct)
    {
        lock (credits)
        {
            if (failure != null) throw new IOException("SMB Direct connection closed.", failure);
            if (CanSend()) return Task.CompletedTask;
            creditWaiter ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
            return creditWaiter.Task.WaitAsync(ct);
        }
    }

    public async ValueTask<byte[]> ReceiveAsync(CancellationToken ct)
    {
        try { return await packets.Reader.ReadAsync(ct).ConfigureAwait(false); }
        catch (ChannelClosedException error) { throw new IOException("SMB Direct connection closed.", error.InnerException ?? error); }
    }

    private async Task ReceiveLoopAsync()
    {
        var ct = stop.Token;
        try
        {
            while (true)
            {
                var incoming = await queue.ReceiveAsync(ct).ConfigureAwait(false);
                if (incoming.Length < 20 || incoming.Length > receiveSize) throw Invalid();
                bool respond = (ReadUInt16LittleEndian(incoming.Span, 4) & 1) != 0;
                bool replenish;
                lock (credits)
                {
                    receivedCount++;
                    lastActivity = clock.GetTimestamp();
                    replyPending |= respond;
                    requested = ReadUInt16LittleEndian(incoming.Span, 0);
                    if (requested == 0 || receiveCredits == 0) throw Invalid();
                    receiveCredits--;
                    sendCredits = checked(sendCredits + ReadUInt16LittleEndian(incoming.Span, 2));
                    if (CanSend())
                    {
                        creditWaiter?.TrySetResult();
                        creditWaiter = null;
                    }
                    respond = replyPending;
                    replenish = receiveCredits <= Math.Min(requested, queue.ReceiveDepth) / 2;
                }
                byte[]? packet = fragments.Append(incoming.Span);
                if (respond || (replenish && packet == null)) await TryPostAsync(ReadOnlyMemory<byte>.Empty, 0, false, ct).ConfigureAwait(false);
                if (packet != null) await packets.Writer.WriteAsync(packet, ct).ConfigureAwait(false);
            }
        }
        catch (Exception error)
        {
            await FailAsync(error).ConfigureAwait(false);
        }
    }

    private async Task KeepaliveAsync()
    {
        var interval = TimeSpan.FromMinutes(2);
        var ct = stop.Token;
        try
        {
            while (true)
            {
                long generation;
                TimeSpan delay;
                lock (credits)
                {
                    delay = interval - clock.GetElapsedTime(lastActivity);
                    generation = receivedCount;
                }
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, clock, ct).ConfigureAwait(false);
                    continue;
                }
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                await TryPostAsync(ReadOnlyMemory<byte>.Empty, 0, true, deadline.Token).ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(5), clock, ct).ConfigureAwait(false);
                lock (credits)
                    if (receivedCount == generation) throw new IOException("SMB Direct keepalive timed out.");
            }
        }
        catch (Exception error)
        {
            await FailAsync(error).ConfigureAwait(false);
        }
    }

    private Task FailAsync(Exception error)
    {
        lock (credits)
        {
            failure ??= error;
            packets.Writer.TryComplete(failure);
            creditWaiter?.TrySetResult();
        }
        return stop.CancelAsync();
    }

    private async ValueTask<bool> TryPostAsync(ReadOnlyMemory<byte> payload, int remaining, bool requestReply, CancellationToken ct)
    {
        await sender.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            int grant;
            lock (credits)
            {
                if (failure != null) throw new IOException("SMB Direct connection closed.", failure);
                if (!CanSend()) return false;
                grant = Math.Max(0, Math.Min(requested, queue.ReceiveDepth) - receiveCredits);
                if (sendCredits == 1) grant = Math.Max(grant, 1);
                if (payload.IsEmpty && grant == 0 && !replyPending && !requestReply) return true;
                replyPending = false;
                sendCredits--;
                receiveCredits += grant;
                lastActivity = clock.GetTimestamp();
            }
            try
            {
                await WriteSegmentAsync(payload, remaining, grant, requestReply, ct).ConfigureAwait(false);
            }
            catch (Exception error)
            {
                // The peer may already have consumed this fragment and its credit grant.
                await FailAsync(error).ConfigureAwait(false);
                throw;
            }
            return true;
        }
        finally { sender.Release(); }
    }

    // MS-SMBD 3.1.5.1 reserves the final send credit for a message granting a receive.
    // Callers hold the credits lock. The provider keeps all available slots preposted.
    private bool CanSend() => sendCredits > 1 || (sendCredits == 1 && receiveCredits < queue.ReceiveDepth);

    private async ValueTask WriteSegmentAsync(ReadOnlyMemory<byte> payload, int remaining, int grant, bool requestReply, CancellationToken ct)
    {
        Outgoing[..DataHeader].Clear();
        WriteUInt16LittleEndian(Outgoing, 0, queue.ReceiveDepth);
        WriteUInt16LittleEndian(Outgoing, 2, grant);
        if (requestReply) WriteUInt16LittleEndian(Outgoing, 4, 1);
        WriteUInt32LittleEndian(Outgoing, 8, (uint)remaining);
        if (!payload.IsEmpty)
        {
            WriteUInt32LittleEndian(Outgoing, 12, DataHeader);
            WriteUInt32LittleEndian(Outgoing, 16, (uint)payload.Length);
            payload.Span.CopyTo(Outgoing[DataHeader..]);
        }
        await queue.SendAsync(payload.IsEmpty ? 20 : DataHeader + payload.Length, ct).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync().ConfigureAwait(false);
        await Task.WhenAll(receiver, keepalive).ConfigureAwait(false);
        stop.Dispose();
        sender.Dispose();
    }

    internal void Abort()
    {
        stop.Cancel();
        queue.Dispose();
    }

    private static SmbException Invalid() => new(NtStatus.InvalidParameter);
}

internal sealed class SmbDirectReassembly
{
    private byte[]? packet;
    private int position;

    internal byte[]? Append(ReadOnlySpan<byte> message)
    {
        if (message.Length < 20) throw new SmbException(NtStatus.InvalidParameter);
        uint remaining = ReadUInt32LittleEndian(message, 8);
        uint offset = ReadUInt32LittleEndian(message, 12);
        uint length = ReadUInt32LittleEndian(message, 16);
        if ((offset & 7) != 0 || offset > message.Length || length > message.Length - offset ||
            length > SmbLimits.MaxFrameSize || remaining > SmbLimits.MaxFrameSize - length)
            throw new SmbException(NtStatus.InvalidParameter);
        if (length == 0)
        {
            if (remaining != 0) throw new SmbException(NtStatus.InvalidParameter);
            return null;
        }
        if (offset < SmbDirectTransport.DataHeader) throw new SmbException(NtStatus.InvalidParameter);
        packet ??= new byte[length + remaining];
        if (packet.Length - position != length + remaining) throw new SmbException(NtStatus.InvalidParameter);
        message.Slice((int)offset, (int)length).CopyTo(packet.AsSpan(position));
        position += (int)length;
        if (remaining != 0) return null;
        var result = packet;
        packet = null;
        position = 0;
        return result;
    }
}
