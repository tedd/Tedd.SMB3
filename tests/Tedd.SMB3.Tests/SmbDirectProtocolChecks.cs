using System.Buffers.Binary;
using System.Threading.Channels;
using Tedd.SMB3;

internal static class SmbDirectProtocolChecks
{
    // A scripted peer can supply independent wire fixtures. Reusing one receive slot
    // ensures that retaining any part of a provider buffer changes previously delivered data.
    private sealed class Peer(int capacity = 512, int depth = 4) : IRdmaQueue
    {
        private readonly byte[] slot = new byte[capacity];
        public int ReceiveDepth => depth;
        public Memory<byte> SendBuffer { get; } = new byte[capacity];
        internal readonly Channel<byte[]> Incoming = Channel.CreateUnbounded<byte[]>();
        internal readonly Channel<byte[]> Outgoing = Channel.CreateUnbounded<byte[]>();
        internal Func<CancellationToken, Task>? BeforeCompletion;
        internal Action? OnReceive;

        public async ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct)
        {
            var next = await Incoming.Reader.ReadAsync(ct);
            Array.Fill(slot, (byte)0xCC);
            next.CopyTo(slot, 0);
            OnReceive?.Invoke();
            return slot.AsMemory(0, next.Length);
        }

        public async ValueTask SendAsync(int length, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (BeforeCompletion != null) await BeforeCompletion(ct);
            await Outgoing.Writer.WriteAsync(SendBuffer[..length].ToArray(), ct);
        }

        internal void Inject(byte[] message)
        {
            if (!Incoming.Writer.TryWrite(message)) throw new InvalidOperationException("Test peer is closed.");
        }

        public void Dispose() => Incoming.Writer.TryComplete();
    }

    private static byte[] Request() => Convert.FromHexString("0001000100000300000200000002000000000200");
    private static byte[] Response() => Convert.FromHexString("0001000100010000030004000000000000000000000200000002000000000200");
    private static void U16(byte[] data, int offset, ushort value) => BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(offset), value);
    private static void U32(byte[] data, int offset, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(offset), value);
    private static uint Read32(byte[] data, int offset) => BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset));
    private static byte[] Segment(ReadOnlySpan<byte> data, int remaining = 0, int offset = 24, int tail = 0)
    {
        byte[] message = new byte[offset + data.Length + tail];
        message.AsSpan().Fill(0xA5);
        message.AsSpan(0, 20).Clear();
        U16(message, 0, 4);
        U16(message, 2, 1);
        U32(message, 8, (uint)remaining);
        U32(message, 12, (uint)offset);
        U32(message, 16, (uint)data.Length);
        data.CopyTo(message.AsSpan(offset));
        return message;
    }

    private static async Task<SmbDirectTransport> OpenAsync(Peer peer, bool server, byte[] negotiation, CancellationToken ct, TimeProvider? clock = null)
    {
        peer.Inject(negotiation);
        var transport = await SmbDirectTransport.NegotiateAsync(peer, server, ct, clock);
        _ = await peer.Outgoing.Reader.ReadAsync(ct);
        return transport;
    }

    internal static async Task RunAsync()
    {
        using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var ct = watchdog.Token;
        await NegotiationAsync(ct);
        Reassembly();
        await WireSizesAsync(ct);
        await ReceiveOwnershipAsync(ct);
        await SendOwnershipAsync(ct);
        await ReceiveLimitsAsync(ct);
        await KeepaliveAsync(ct);
        await FailuresAsync(ct);
        Console.WriteLine("PASS SMB Direct negotiation limits, wire sizes, borrowed slots, reassembly, backpressure and provider failures");
    }

    private static async Task NegotiationAsync(CancellationToken ct)
    {
        foreach (bool server in new[] { true, false })
        {
            var valid = server ? Request() : Response();
            for (int length = 0; length < valid.Length; length++)
            {
                using var peer = new Peer();
                peer.Inject(valid[..length]);
                await Check.StatusAsync(NtStatus.InvalidParameter, () => SmbDirectTransport.NegotiateAsync(peer, server, ct).AsTask(), $"short {(server ? "request" : "response")} length {length}");
            }
            int sizes = server ? 8 : 20;
            var cases = new List<(string Label, Action<byte[]> Change)>
            {
                ("no requested credits", b => U16(b, server ? 6 : 8, 0)),
                ("small receive size", b => U32(b, sizes + 4, 127)),
                ("small fragmented limit", b => U32(b, sizes + 8, 131071))
            };
            if (!server)
            {
                cases.Add(("no granted credits", b => U16(b, 10, 0)));
                cases.Add(("unsupported negotiated dialect", b => U16(b, 4, 0x101)));
                cases.Add(("preferred size exceeds offer", b => U32(b, 20, 513)));
            }
            foreach (var (label, change) in cases)
            {
                using var peer = new Peer();
                var message = valid.ToArray();
                change(message);
                peer.Inject(message);
                await Check.StatusAsync(NtStatus.InvalidParameter, () => SmbDirectTransport.NegotiateAsync(peer, server, ct).AsTask(), label);
            }
            using var waiting = new Peer();
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var negotiation = SmbDirectTransport.NegotiateAsync(waiting, server, cancel.Token).AsTask();
            cancel.Cancel();
            await Check.ThrowsAsync<OperationCanceledException>(() => negotiation, "cancel negotiation");
            foreach (var (capacity, depth) in new[] { (127, 4), (512, 1), (512, 65536) })
            {
                using var tooSmall = new Peer(capacity, depth);
                await Check.ThrowsAsync<ArgumentException>(() => SmbDirectTransport.NegotiateAsync(tooSmall, server, ct).AsTask(), "provider capacity");
            }
        }
        using var ranged = new Peer();
        byte[] request = Request();
        U16(request, 0, 0xff);
        U16(request, 2, 0x101);
        U16(request, 6, ushort.MaxValue);
        U32(request, 8, 0);
        U32(request, 12, uint.MaxValue);
        U32(request, 16, uint.MaxValue);
        ranged.Inject(request);
        await using var accepted = await SmbDirectTransport.NegotiateAsync(ranged, true, ct);
        byte[] reply = await ranged.Outgoing.Reader.ReadAsync(ct);
        Check.Equal((ushort)4, BinaryPrimitives.ReadUInt16LittleEndian(reply.AsSpan(10)), "grant capped at posted depth");
        Check.Equal(512u, Read32(reply, 20), "send capped at provider capacity");
        Check.Equal(128u, Read32(reply, 24), "minimum receive size");
    }

    private static void Reassembly()
    {
        var assembler = new SmbDirectReassembly();
        var rng = new Random(39017);
        byte[] control = new byte[20];
        for (int trial = 0; trial < 128; trial++)
        {
            byte[] expected = new byte[rng.Next(1, 32000)];
            rng.NextBytes(expected);
            byte[]? completed = null;
            for (int pos = 0; pos < expected.Length;)
            {
                int count = Math.Min(rng.Next(1, 1025), expected.Length - pos);
                int remaining = expected.Length - pos - count;
                var segment = Segment(expected.AsSpan(pos, count), remaining, 24 + 8 * rng.Next(5), rng.Next(8));
                completed = assembler.Append(segment);
                Array.Clear(segment);
                if (remaining != 0) Check.Equal<byte[]?>(null, completed, "no early packet delivery");
                Check.Equal<byte[]?>(null, assembler.Append(control), "control delivers no data");
                pos += count;
            }
            Check.Bytes(expected, completed!, $"seed 39017 partition {trial}");
        }
    }

    private static async Task WireSizesAsync(CancellationToken ct)
    {
        using var peer = new Peer();
        byte[] response = Response();
        U32(response, 24, 128);
        U16(response, 10, 8);
        await using var transport = await OpenAsync(peer, false, response, ct);
        var payload = Enumerable.Range(0, 209).Select(i => (byte)i).ToArray();
        await transport.SendAsync(payload, ct);
        int pos = 0;
        foreach (int size in new[] { 104, 104, 1 })
        {
            byte[] message = await peer.Outgoing.Reader.ReadAsync(ct);
            Check.Equal(size + 24, message.Length, "exact wire length");
            Check.Equal((uint)(payload.Length - pos - size), Read32(message, 8), "outbound remaining length");
            Check.Equal(24u, Read32(message, 12), "outbound aligned data offset");
            Check.Equal((uint)size, Read32(message, 16), "outbound data length");
            Check.Bytes(payload[pos..(pos + size)], message[24..], "wire fragment payload");
            Check.Bytes(new byte[4], message[20..24], "wire padding cleared");
            pos += size;
        }
        await Check.StatusAsync(NtStatus.InvalidParameter, () => transport.SendAsync(new byte[131073], ct).AsTask(), "remote fragmented limit");
        await Check.StatusAsync(NtStatus.InvalidParameter, () => transport.SendAsync(Array.Empty<byte>(), ct).AsTask(), "empty application packet");
        Check.Equal(false, peer.Outgoing.Reader.TryRead(out _), "no invalid send posted");
    }

    private static async Task ReceiveOwnershipAsync(CancellationToken ct)
    {
        using var peer = new Peer();
        await using var transport = await OpenAsync(peer, true, Request(), ct);
        byte[] first = Enumerable.Repeat((byte)0x17, 201).ToArray();
        byte[] second = Enumerable.Repeat((byte)0x8f, 115).ToArray();
        peer.Inject(Segment(first.AsSpan(0, 64), first.Length - 64));
        peer.Inject(Segment(first.AsSpan(64)));
        var saved = await transport.ReceiveAsync(ct);
        peer.Inject(Segment(second));
        Check.Bytes(second, await transport.ReceiveAsync(ct), "next completed packet");
        Check.Bytes(first, saved, "first packet survives reuse of same provider slot");

        using var cancelled = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var interrupted = transport.ReceiveAsync(cancelled.Token).AsTask();
        cancelled.Cancel();
        await Check.ThrowsAsync<OperationCanceledException>(() => interrupted, "cancel application read");
        await transport.SendAsync("response"u8.ToArray(), ct); // Return credits for the next request.
        peer.Inject(Segment("next"u8));
        Check.Bytes("next"u8.ToArray(), await transport.ReceiveAsync(ct), "cancelled read preserves next packet");
    }

    private static async Task SendOwnershipAsync(CancellationToken ct)
    {
        using var peer = new Peer();
        await using var transport = await OpenAsync(peer, false, Response(), ct);
        var posted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var receive = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        peer.BeforeCompletion = token => { posted.TrySetResult(); return release.Task.WaitAsync(token); };
        var send = transport.SendAsync("outstanding"u8.ToArray(), ct).AsTask();
        try
        {
            await posted.Task.WaitAsync(ct);
            peer.OnReceive = () => receive.TrySetResult();
            peer.Inject(Convert.FromHexString("0400010001000000000000000000000000000000"));
            await receive.Task.WaitAsync(ct);
        }
        finally { release.TrySetResult(); }
        await send;
        byte[] data = await peer.Outgoing.Reader.ReadAsync(ct);
        Check.Bytes("outstanding"u8.ToArray(), data[24..], "control traffic preserves pending send slot");
        byte[] control = await peer.Outgoing.Reader.ReadAsync(ct);
        Check.Equal(20, control.Length, "control reply follows completion of data send");
    }

    private static async Task ReceiveLimitsAsync(CancellationToken ct)
    {
        var noRequest = Segment("x"u8);
        U16(noRequest, 0, 0);
        foreach (var (server, frame, label) in new[]
        {
            (false, Segment("x"u8), "data before initial receive grant"),
            (true, noRequest, "zero credit request"),
            (true, new byte[19], "short transfer header"),
            (true, Segment(new byte[105]), "transfer exceeds negotiated receive size")
        })
        {
            using var peer = new Peer();
            byte[] negotiation = server ? Request() : Response();
            U32(negotiation, server ? 8 : 20, 128);
            await using var transport = await OpenAsync(peer, server, negotiation, ct);
            peer.Inject(frame);
            var error = await Check.ThrowsAsync<IOException>(() => transport.ReceiveAsync(ct).AsTask(), label);
            Check.Equal(NtStatus.InvalidParameter, ((SmbException)error.GetBaseException()).NtStatus, label);
        }
    }

    // Each keepalive delay registers one one-shot timer. Await registration before
    // stepping it so the tests never depend on thread-pool scheduling or wall time.
    private sealed class Clock : TimeProvider
    {
        private long ticks;
        private readonly Channel<Alarm> alarms = Channel.CreateUnbounded<Alarm>();
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Interlocked.Read(ref ticks);
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            Check.Equal(Timeout.InfiniteTimeSpan, period, "one-shot keepalive timer");
            var alarm = new Alarm(callback, state, dueTime, GetTimestamp() + dueTime.Ticks);
            alarms.Writer.TryWrite(alarm);
            return alarm;
        }
        private sealed class Alarm(TimerCallback callback, object? state, TimeSpan delay, long due) : ITimer
        {
            internal readonly TimeSpan Delay = delay;
            internal readonly long Due = due;
            private int disposed;
            internal void Fire()
            {
                if (Volatile.Read(ref disposed) == 0) callback(state);
            }
            public bool Change(TimeSpan dueTime, TimeSpan period) => throw new NotSupportedException();
            public void Dispose() => Interlocked.Exchange(ref disposed, 1);
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
        internal async Task StepAsync(int expectedSeconds, CancellationToken ct)
        {
            var alarm = await alarms.Reader.ReadAsync(ct);
            Check.Equal(TimeSpan.FromSeconds(expectedSeconds), alarm.Delay, "keepalive timer interval");
            Interlocked.Exchange(ref ticks, alarm.Due);
            alarm.Fire();
        }
    }

    private static async Task KeepaliveAsync(CancellationToken ct)
    {
        using var peer = new Peer();
        var clock = new Clock();
        await using var transport = await OpenAsync(peer, false, Response(), ct, clock);
        await clock.StepAsync(120, ct);
        byte[] probe = await peer.Outgoing.Reader.ReadAsync(ct);
        Check.Equal(20, probe.Length, "idle probe carries no payload");
        Check.Equal((ushort)1, BinaryPrimitives.ReadUInt16LittleEndian(probe.AsSpan(4)), "idle probe requests reply");
        peer.Inject(Segment("ack"u8));
        Check.Bytes("ack"u8.ToArray(), await transport.ReceiveAsync(ct), "data satisfies keepalive");
        await clock.StepAsync(5, ct);
        await clock.StepAsync(115, ct);
        probe = await peer.Outgoing.Reader.ReadAsync(ct);
        Check.Equal((byte)1, probe[4], "next idle period sends another probe");
        var read = transport.ReceiveAsync(ct).AsTask();
        await clock.StepAsync(5, ct);
        var failure = await Check.ThrowsAsync<IOException>(() => read, "unanswered keepalive terminates reader");
        Check.Equal("SMB Direct keepalive timed out.", failure.GetBaseException().Message, "original timeout reaches application");
        await Check.ThrowsAsync<IOException>(() => transport.SendAsync(new byte[1], ct).AsTask(), "timed-out connection rejects data");
    }

    private static async Task FailuresAsync(CancellationToken ct)
    {
        using (var peer = new Peer())
        {
            await using var transport = await OpenAsync(peer, false, Response(), ct);
            var blocked = transport.ReceiveAsync(ct).AsTask();
            peer.Incoming.Writer.TryComplete(new IOException("receive completion failed"));
            await Check.ThrowsAsync<IOException>(() => blocked, "failed provider wakes reader");
            await Check.ThrowsAsync<IOException>(() => transport.SendAsync(new byte[3], ct).AsTask(), "failed provider rejects sends");
        }
        using (var peer = new Peer())
        {
            await using var transport = await OpenAsync(peer, true, Request(), ct);
            var waiter = transport.SendAsync(new byte[1], ct).AsTask();
            Check.Equal(false, waiter.IsCompleted, "server initially has no outgoing credits");
            peer.Incoming.Writer.TryComplete(new IOException("peer closed"));
            await Check.ThrowsAsync<IOException>(() => waiter, "provider closure wakes credit waiter");
        }
        using (var peer = new Peer())
        {
            var transport = await OpenAsync(peer, true, Request(), ct);
            // The second delivery blocks on the full application channel until shutdown.
            peer.Inject(Segment("first"u8));
            peer.Inject(Segment("second"u8));
            await transport.DisposeAsync().AsTask().WaitAsync(ct);
        }
        using (var peer = new Peer())
        {
            byte[] response = Response();
            U16(response, 10, 1);
            U32(response, 24, 128);
            await using var transport = await OpenAsync(peer, false, response, ct);
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var reading = transport.ReceiveAsync(ct).AsTask();
            var sending = transport.SendAsync(new byte[105], cancel.Token).AsTask();
            Check.Equal(1u, Read32(await peer.Outgoing.Reader.ReadAsync(ct), 8), "first fragment promises one more byte");
            cancel.Cancel();
            await Check.ThrowsAsync<OperationCanceledException>(() => sending, "cancel fragmented send between credits");
            await Check.ThrowsAsync<IOException>(() => reading.WaitAsync(ct), "partial cancelled message terminates connection");
        }
        using (var peer = new Peer())
        {
            await using var transport = await OpenAsync(peer, false, Response(), ct);
            var read = transport.ReceiveAsync(ct).AsTask();
            peer.BeforeCompletion = _ => Task.FromException(new IOException("send completion failed"));
            await Check.ThrowsAsync<IOException>(() => transport.SendAsync(new byte[17], ct).AsTask(), "failed send completion reported");
            await Check.ThrowsAsync<IOException>(() => read.WaitAsync(ct), "failed send completion wakes reader");
            peer.BeforeCompletion = null;
            await Check.ThrowsAsync<IOException>(() => transport.SendAsync(new byte[17], ct).AsTask(), "cannot reuse indeterminate send credits");
        }
    }
}
