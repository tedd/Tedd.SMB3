using System.Net;
using Tedd.SMB3;

internal static class LinuxRdmaChecks
{
    // Run on a Linux RoCE interface that permits connections to its own address.
    internal static async Task RunAsync(string address)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("Linux RDMA requires Linux.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var ct = deadline.Token;
        using var listener = RdmaProvider.Listen(new(IPAddress.Parse(address), 0), 4, out var bound);
        Check.Equal(true, bound.Port != 0, "RDMA ephemeral port");

        using (var stop = new CancellationTokenSource())
        {
            var pending = listener.AcceptAsync(stop.Token);
            stop.CancelAfter(TimeSpan.FromMilliseconds(100));
            await Check.ThrowsAsync<OperationCanceledException>(() => pending, "cancel native accept");
        }

        var connect = RdmaProvider.ConnectAsync(address, bound.Port, ct);
        using var server = await listener.AcceptAsync(ct);
        await server.FinishAcceptAsync(ct);
        using var client = await connect;

        static async Task Transfer(IRdmaQueue source, IRdmaQueue target, CancellationToken ct)
        {
            int[] lengths = [1, 37, source.SendBuffer.Length - 1, source.SendBuffer.Length];
            for (int i = 0; i < 4 * source.ReceiveDepth; i++)
            {
                int length = lengths[i % lengths.Length];
                var send = source.SendBuffer[..length];
                send.Span.Fill((byte)i);
                await source.SendAsync(length, ct);
                var received = await target.ReceiveAsync(ct);
                Check.Equal(true, send.Span.SequenceEqual(received.Span), "registered slot length and contents");
            }
        }

        await Task.WhenAll(Transfer(client, server, ct), Transfer(server, client, ct));
        await Check.ThrowsAsync<IOException>(() => client.SendAsync(client.SendBuffer.Length + 1, ct).AsTask(), "oversized native send");

        using (var stop = new CancellationTokenSource())
        {
            var waiting = server.ReceiveAsync(stop.Token).AsTask();
            stop.CancelAfter(TimeSpan.FromMilliseconds(100));
            await Check.ThrowsAsync<OperationCanceledException>(() => waiting.WaitAsync(ct), "cancel posted receive");
        }

        var disconnect = client.ReceiveAsync(ct).AsTask();
        server.Dispose();
        await Check.ThrowsAsync<IOException>(() => disconnect.WaitAsync(ct), "peer disconnect wakes receive");
        Console.WriteLine("PASS native Linux RDMA listen, accept cancellation, duplex transfers, slot rotation and disconnect");
    }
}
