using System.Threading.Channels;
using Tedd.SMB3;

internal static class SmbDirectChecks
{
    // The fake preserves RDMA SEND boundaries and fails immediately on a receive queue overrun.
    private sealed class Queue(Channel<byte[]> incoming, Channel<byte[]> outgoing, int size, int? advertisedLimit = null) : IRdmaQueue
    {
        private bool firstSend = true;
        public int ReceiveDepth => 4;
        public Memory<byte> SendBuffer { get; } = new byte[size];
        public ValueTask SendAsync(int length, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var message = SendBuffer[..length].ToArray();
            if (firstSend && advertisedLimit.HasValue)
                Wire.WriteUInt32LittleEndian(message, length - 4, (uint)advertisedLimit.Value);
            firstSend = false;
            if (!outgoing.Writer.TryWrite(message))
                throw new InvalidOperationException("RDMA work request exceeds the posted receive capacity.");
            return ValueTask.CompletedTask;
        }
        public async ValueTask<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct)
        {
            return await incoming.Reader.ReadAsync(ct);
        }
        public void Dispose() => outgoing.Writer.TryComplete();
    }

    internal static async Task RunAsync()
    {
        await SmbDirectProtocolChecks.RunAsync();
        await FileSessionsAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var ct = timeout.Token;
        var a = Channel.CreateBounded<byte[]>(4);
        var b = Channel.CreateBounded<byte[]>(4);
        using var clientQueue = new Queue(a, b, 4096);
        using var serverQueue = new Queue(b, a, 1024);
        var serverStart = SmbDirectTransport.NegotiateAsync(serverQueue, true, ct);
        await using var client = await SmbDirectTransport.NegotiateAsync(clientQueue, false, ct);
        await using var server = await serverStart;
        var random = new Random(431);
        foreach (int length in new[] { 16, 999, 1000, 1001, 65536, 1048577, SmbLimits.MaxFrameSize })
        {
            byte[] request = new byte[length], response = new byte[length + (length == SmbLimits.MaxFrameSize ? -1 : 1)];
            random.NextBytes(request);
            random.NextBytes(response);
            async Task Respond()
            {
                Check.Bytes(request, await server.ReceiveAsync(ct), "SMBD reassembled request");
                await server.SendAsync(response, ct);
            }
            var peer = Respond();
            await client.SendAsync(request, ct);
            Check.Bytes(response, await client.ReceiveAsync(ct), "SMBD reassembled response");
            await peer;
        }
        await Check.StatusAsync(NtStatus.InvalidParameter, () => client.SendAsync(new byte[SmbLimits.MaxFrameSize + 1], ct).AsTask(), "SMBD negotiated send limit");

        using (var origin = new SessionCrypto(new byte[16], new byte[64], false))
        using (var peer = new SessionCrypto(new byte[16], new byte[64], true))
        {
            var data = new byte[65536];
            random.NextBytes(data);
            var smb = Wire.Packet(Smb3Command.Write, 1, 42, 1, data);
            origin.Sign(smb);
            var received = server.ReceiveAsync(ct);
            await client.SendAsync(origin.Encrypt(smb, 42), ct);
            byte[] decrypted = peer.Decrypt(await received, 42);
            peer.Verify(decrypted);
            Check.Bytes(smb, decrypted, "SMBD preserves a protected SMB message across fragments");
        }

        // Fixed wire vectors independent of production encoders and constants.
        var offers = Channel.CreateBounded<byte[]>(4);
        var replies = Channel.CreateBounded<byte[]>(4);
        using var wire = new Queue(offers, replies, 1024);
        var start = SmbDirectTransport.NegotiateAsync(wire, true, ct);
        offers.Writer.TryWrite(Convert.FromHexString("0001000100000200000400000004000000000200"));
        var transport = await start;
        Check.Bytes(Convert.FromHexString("0001000100010000040002000000000000000000000400000004000000004000"),
            await replies.Reader.ReadAsync(ct), "SMBD negotiate response fixture");
        offers.Writer.TryWrite(Convert.FromHexString("0200020001000000000000000000000000000000"));
        Check.Bytes(Convert.FromHexString("0400010000000000000000000000000000000000"), await replies.Reader.ReadAsync(ct), "SMBD keepalive reply with credit");
        offers.Writer.TryWrite(Convert.FromHexString("020001000000000000000000180000000300000000000000616263"));
        Check.Bytes("abc"u8.ToArray(), await transport.ReceiveAsync(ct), "SMBD payload after empty control");
        await transport.DisposeAsync();
        var reject = SmbDirectTransport.NegotiateAsync(wire, true, ct);
        offers.Writer.TryWrite(Convert.FromHexString("0002000200000200000400000004000000000200"));
        await Check.StatusAsync(NtStatus.NotSupported, () => reject.AsTask(), "SMBD version range");
        Check.Bytes(Convert.FromHexString("000100010000000000000000BB0000C000000000000000000000000000000000"),
            await replies.Reader.ReadAsync(ct), "SMBD version failure fixture");

        var initiated = SmbDirectTransport.NegotiateAsync(wire, false, ct);
        Check.Bytes(Convert.FromHexString("0001000100000400000400000004000000004000"), await replies.Reader.ReadAsync(ct), "SMBD negotiate request fixture");
        offers.Writer.TryWrite(Convert.FromHexString("0001000100010000040002000000000000000000000400000004000000004000"));
        await using (var credited = await initiated)
        {
            await credited.SendAsync("first"u8.ToArray(), ct);
            var firstSend = await replies.Reader.ReadAsync(ct);
            Check.Equal((byte)4, firstSend[2], "first SMBD send grants preposted receives");
            using var interrupted = new CancellationTokenSource();
            var blocked = credited.SendAsync("second"u8.ToArray(), interrupted.Token);
            Check.Equal(false, blocked.IsCompleted, "final SMBD send credit reserved");
            interrupted.Cancel();
            await Check.ThrowsAsync<OperationCanceledException>(() => blocked.AsTask(), "cancel while waiting for SMBD credit");
            var resumed = credited.SendAsync("second"u8.ToArray(), ct);
            offers.Writer.TryWrite(Convert.FromHexString("0400000000000000000000000000000000000000"));
            await resumed;
            var lastSend = await replies.Reader.ReadAsync(ct);
            Check.Equal((byte)1, lastSend[2], "final SMBD send credit carries replacement credit");
        }
        var declined = SmbDirectTransport.NegotiateAsync(wire, false, ct);
        _ = await replies.Reader.ReadAsync(ct);
        offers.Writer.TryWrite(Convert.FromHexString("000100010000000000000000BB0000C000000000000000000000000000000000"));
        await Check.StatusAsync(NtStatus.NotSupported, () => declined.AsTask(), "SMBD negotiate failure status");

        var assembler = new SmbDirectReassembly();
        byte[] first = Convert.FromHexString("04000100000000000200000018000000010000000000000061");
        Check.Equal<byte[]?>(null, assembler.Append(first), "SMBD incomplete fragment");
        Check.Equal<byte[]?>(null, assembler.Append(new byte[20]), "SMBD control between fragments");
        foreach (string malformed in new[] {
            "0000", // truncated header
            "040001000000000000000000FFFFFFFF01000000", // wrapping offset
            "0400010000000000FFFFFFFF18000000010000000000000061", // wrapping total
            "0400010000000000000000000800000001000000", // payload overlaps header
            "0400010000000000000000001900000001000000000000000061", // misaligned
            "04000100000000000000000018000000010000000000000061" // premature final fragment
        })
        {
            await Check.StatusAsync(NtStatus.InvalidParameter, () => { assembler.Append(Convert.FromHexString(malformed)); return Task.CompletedTask; }, "SMBD invalid segment");
        }
        Check.Bytes("abc"u8.ToArray(), assembler.Append(Convert.FromHexString("0400010000000000000000001800000002000000000000006263"))!, "SMBD final fragment");
        Console.WriteLine("PASS SMB Direct negotiation, credit exhaustion, fragmented messages, control traffic and wire fixtures");
    }

    private static async Task FileSessionsAsync()
    {
        using var watchdog = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        foreach (var (clientEncrypt, serverEncrypt) in new[] { (false, false), (true, false), (false, true) })
        {
            var ct = watchdog.Token;
            var store = new ProviderChecks.MemoryProvider();
            await using var host = new SmbServer(new()
            {
                UserName = "fixture", Password = "fixture-secret", UseSmbDirect = true,
                RequireEncryption = serverEncrypt, Shares = [new("data", store) { Writable = true }]
            });
            var requests = Channel.CreateBounded<byte[]>(4);
            var replies = Channel.CreateBounded<byte[]>(4);
            const int peerLimit = 131072;
            using var clientQueue = new Queue(replies, requests, 4096, peerLimit);
            using var serverQueue = new Queue(requests, replies, 1024, peerLimit);
            using var shutdown = CancellationTokenSource.CreateLinkedTokenSource(ct);
            async Task Serve()
            {
                await using var direct = await SmbDirectTransport.NegotiateAsync(serverQueue, true, shutdown.Token);
                await using var connection = new ServerConnection(host);
                await connection.RunAsync(direct, shutdown.Token);
                Check.Equal(true, connection.LoggedOff, "RDMA session completed LOGOFF");
            }
            var serving = Serve();
            try
            {
                var options = new SmbClientOptions
                {
                    UseSmbDirect = true, UserName = "fixture", Password = "fixture-secret", Encrypt = clientEncrypt,
                    OpenRdmaQueue = (_, _, _) => Task.FromResult<IRdmaQueue>(clientQueue)
                };
                await using (var client = await SmbClient.ConnectAsync("fixture", "data", options, ct))
                {
                    Check.Equal(clientEncrypt || serverEncrypt, client.IsEncrypted, "negotiated file protection");
                    Check.Equal(false, client.IsCompressionEnabled, "in-band RDMA compression policy");
                    byte[] data = new byte[262177];
                    new Random(743).NextBytes(data);
                    await client.WriteAllBytesAsync("original.bin", data, ct);
                    await client.MoveAsync("original.bin", "renamed.bin", ct: ct);
                    await Check.StatusAsync(NtStatus.ObjectNameNotFound, () => client.ReadAllBytesAsync("original.bin", ct), "SMB error on RDMA");
                    Check.Bytes(data, await client.ReadAllBytesAsync("renamed.bin", ct), "protected file READ after SMB error");
                    await using (var file = await client.OpenAsync("renamed.bin", ct: ct))
                    {
                        byte[] buffer = new byte[data.Length];
                        int read = await file.ReadAsync(buffer, 0, ct);
                        Check.Equal(peerLimit - 52 - 64 - 48, read, "bulk read fits negotiated SMBD limit including headers");
                        Check.Bytes(data[..read], buffer[..read], "transport-limited read payload");
                    }
                    using (var stored = store.OpenFile("renamed.bin", FileMode.Open, FileAccess.Read, FileShare.Read, writeThrough: false))
                    {
                        var actual = new byte[data.Length];
                        Check.Equal(data.Length, await stored.ReadAsync(actual, 0, ct), "provider received full WRITE");
                        Check.Bytes(data, actual, "provider contents match independent input");
                    }
                    await client.DeleteAsync("renamed.bin", ct: ct);
                }
                await serving.WaitAsync(ct);
            }
            finally
            {
                shutdown.Cancel();
                try { await serving; } catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }
        Console.WriteLine("PASS SMB Direct authenticated file sessions, signing, encryption policy and logoff");
    }
}
