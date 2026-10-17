using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Tedd.Smb;

/// <summary>Boundary and ownership regressions for reusable crypto, framing, and async I/O.</summary>
internal static class AllocationRefactorChecks
{
    internal static async Task RunAsync(string root)
    {
        CryptoVectors();
        await FragmentedTransportAsync();
        await ConcurrentClientsAsync(root);
    }

    private static void CryptoVectors()
    {
        byte[] key = Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C");
        byte[] message = Convert.FromHexString(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51" +
            "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
        // NIST SP 800-38B examples exercise padded and complete final blocks.
        Check(Crypto.Cmac(key, message[..40]), Convert.FromHexString("DFA66747DE9AE63030CA32611497C827"));
        Check(Crypto.Cmac(key, message), Convert.FromHexString("51F0BEBF7E3B9D92FC49741779363CFE"));
        Check(Crypto.Md4(System.Text.Encoding.ASCII.GetBytes(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
            Convert.FromHexString("E33B4DDC9C38F2199C3E7B164FCC0536"));

        foreach (int cipher in new[] { Smb3Cipher.Aes128Gcm, Smb3Cipher.Aes128Ccm })
        {
            using var sender = new SessionCrypto(new byte[16], new byte[64], false, cipher);
            using var receiver = new SessionCrypto(new byte[16], new byte[64], true, cipher);
            foreach (int length in new[] { 64, 65, 79, 80, 81, 4096, 65536 })
            {
                byte[] packet = RandomNumberGenerator.GetBytes(length);
                Wire.Header(13, 1, 42).CopyTo(packet, 0);
                sender.Sign(packet);
                byte[] original = (byte[])packet.Clone();
                receiver.Verify(packet);
                Check(packet, original);
                // Reusing the CMAC instance must not retain state from the previous packet.
                sender.Sign(packet);
                Check(packet, original);
                receiver.Verify(packet);
                byte[] first = sender.Encrypt(packet, 42);
                byte[] second = sender.Encrypt(packet, 42);
                if (first.AsSpan(20, 16).SequenceEqual(second.AsSpan(20, 16))) throw new Exception("Nonce reused.");
                Check(receiver.Decrypt(first, 42), packet);
                Check(receiver.Decrypt(second, 42), packet);

                packet[^1] ^= 1;
                byte[] tampered = (byte[])packet.Clone();
                try { receiver.Verify(packet); throw new Exception("Invalid signature accepted."); }
                catch (SmbException e) when (e.NtStatus == NtStatus.AccessDenied) { }
                Check(packet, tampered);
                first[^1] ^= 1;
                try { receiver.Decrypt(first, 42); throw new Exception("Invalid tag accepted."); }
                catch (CryptographicException) { }
            }
        }
        Console.WriteLine("PASS NIST multiblock CMAC, MD4 padding, GCM/CCM boundaries, nonce uniqueness and immutable verification");
    }

    private static async Task FragmentedTransportAsync()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, timeout.Token);
        using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
        var transport = new SmbTransport(client.GetStream());
        byte[] packet = Wire.Packet(13, 1, 0, 0, [4, 0, 0, 0]);
        byte[] frame = new byte[4 + packet.Length];
        frame[3] = (byte)packet.Length;
        packet.CopyTo(frame, 4);
        var receive = transport.ReceiveAsync(timeout.Token);
        // Split the transport header and payload at arbitrary byte boundaries.
        for (int offset = 0; offset < frame.Length; offset += 3)
            await peer.GetStream().WriteAsync(frame.AsMemory(offset, Math.Min(3, frame.Length - offset)), timeout.Token);
        Check(await receive, packet);

        await transport.SendAsync(packet, timeout.Token);
        byte[] received = new byte[frame.Length];
        await peer.GetStream().ReadExactlyAsync(received, timeout.Token);
        Check(received, frame);

        // Cancellation before a write must release its rental even on the error path.
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        try { await transport.SendAsync(packet, canceled.Token); throw new Exception("Cancellation ignored."); }
        catch (OperationCanceledException) { }

        await peer.GetStream().WriteAsync(frame.AsMemory(0, 7), timeout.Token);
        peer.Dispose();
        try { await transport.ReceiveAsync(timeout.Token); throw new Exception("Truncated frame accepted."); }
        catch (EndOfStreamException) { }
        Console.WriteLine("PASS fragmented framing, pooled send, cancellation and truncated payload");
    }

    private static async Task ConcurrentClientsAsync(string root)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var server = new SmbServer(new()
        {
            RootPath = root,
            UserName = "smbtest",
            Password = "testpass",
            Writable = true,
            Port = 0
        });
        Task run = server.RunAsync(timeout.Token);
        try
        {
            await Task.WhenAll(Enumerable.Range(0, 4).Select(async worker =>
            {
                await using var client = await SmbClient.ConnectAsync("127.0.0.1", "files", new()
                {
                    UserName = "smbtest",
                    Password = "testpass",
                    Port = server.LocalEndPoint.Port
                }, timeout.Token);
                string path = $"async-worker-{worker}.bin";
                byte[] contents = RandomNumberGenerator.GetBytes(131079 + worker);
                await client.WriteAllBytesAsync(path, contents, timeout.Token);
                Check(await client.ReadAllBytesAsync(path, timeout.Token), contents);
                using var canceled = new CancellationTokenSource();
                canceled.Cancel();
                try { await client.GetInfoAsync(path, ct: canceled.Token); throw new Exception("Canceled request ran."); }
                catch (OperationCanceledException) { }
                // Cancellation while waiting for the channel does not consume its credits.
                Check(await client.ReadAllBytesAsync(path, timeout.Token), contents);
                await client.DeleteAsync(path, ct: timeout.Token);
            }));
        }
        finally { timeout.Cancel(); await run; }
        Console.WriteLine("PASS concurrent encrypted clients and cancellation before channel acquisition");
    }

    private static void Check(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected)
    {
        if (!actual.SequenceEqual(expected)) throw new Exception("Byte mismatch.");
    }
}
