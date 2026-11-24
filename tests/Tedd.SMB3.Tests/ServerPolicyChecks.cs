using Tedd.SMB3;

internal static class ServerPolicyChecks
{
    internal static async Task RunAsync(string root)
    {
        string export = Directory.CreateDirectory(Path.Combine(root, $"server-policy-{Guid.NewGuid():N}")).FullName;
        try
        {
            await ConfigurationAsync(export);
            await NegotiationAsync(export);
            await ReadOnlyAsync(export);
        }
        finally { Directory.Delete(export, true); }
    }

    private static async Task ConfigurationAsync(string export)
    {
        var provider = SmbDirectoryProvider.Create(export);
        var options = new SmbServerOptions { UserName = "user", Password = "password", Port = 0 };
        async Task Construct(SmbServerOptions candidate)
        {
            await using var server = new SmbServer(candidate);
        }

        foreach (string name in new[] { "", " ", ".", "..", "ends.", "ends ", "iPc$", new string('s', 81) }
            .Concat("\\/:*?\"<>|\u001f".Select(c => $"left{c}right")))
        {
            await Check.ThrowsAsync<ArgumentException>(() => Construct(options with { Shares = [new(name, provider)] }),
                $"invalid share name {name}");
        }
        var named = new SmbShare(new string('s', 80), provider);
        var one = options with { Shares = [named] };
        await Construct(one with { MaxConnections = 1 });
        await Construct(one with { MaxConnections = 1024 });
        foreach (int count in new[] { -1, 0, 1025 })
            await Check.ThrowsAsync<ArgumentOutOfRangeException>(() => Construct(one with { MaxConnections = count }), $"connection limit {count}");
        var shares = Enumerable.Range(0, 257).Select(i => new SmbShare($"share{i}", provider)).ToArray();
        await Construct(options with { Shares = shares[..256] });
        await Check.ThrowsAsync<ArgumentException>(() => Construct(options with { Shares = shares }), "257 shares");
        await Check.ThrowsAsync<ArgumentException>(() => Construct(options), "empty share registry");
        await Check.ThrowsAsync<ArgumentException>(() => Construct(one with { RootPath = export }), "mixed share configuration");
        await Check.ThrowsAsync<ArgumentException>(() => Construct(one with { UserName = " " }), "blank account");
        await Check.ThrowsAsync<ArgumentException>(() => Construct(one with { Password = "" }), "empty password");
        Console.WriteLine("PASS server configuration, share names, registry size and connection limit boundaries");
    }

    private static async Task NegotiationAsync(string export)
    {
        bool[] flags = [false, true];
        byte[] data = Enumerable.Repeat((byte)0x37, 65537).ToArray();
        const string path = "policy.bin";
        foreach (bool requireEncryption in flags)
        foreach (bool offerCompression in flags)
        {
            using var stop = new CancellationTokenSource();
            await using var server = new SmbServer(new()
            {
                RootPath = export, Port = 0, Writable = true, UserName = "user", Password = "password",
                RequireEncryption = requireEncryption, EnableCompression = offerCompression
            });
            var run = server.RunAsync(stop.Token);
            try
            {
                foreach (bool encrypt in flags)
                foreach (bool compress in flags)
                {
                    var options = new SmbClientOptions
                    {
                        UserName = "user", Password = "password", Port = server.LocalEndPoint.Port,
                        Encrypt = encrypt, EnableCompression = compress
                    };
                    await using var client = await SmbClient.ConnectAsync("127.0.0.1", "files", options);
                    string scenario = $"server encryption={requireEncryption}, compression={offerCompression}; client encryption={encrypt}, compression={compress}";
                    Check.Equal("3.1.1", client.Dialect, scenario);
                    Check.Equal(requireEncryption || encrypt, client.IsEncrypted, scenario);
                    Check.Equal(offerCompression && compress, client.IsCompressionEnabled, scenario);
                    await client.WriteAllBytesAsync(path, data);
                    Check.Bytes(data, File.ReadAllBytes(Path.Combine(export, path)), scenario);
                    Check.Bytes(data, await client.ReadAllBytesAsync(path), scenario);
                    await client.DeleteAsync(path);
                }
            }
            finally { stop.Cancel(); await run; }
        }
        Console.WriteLine("PASS file transfers for all 16 client/server encryption and compression policies");
    }

    private static async Task ReadOnlyAsync(string export)
    {
        const string file = "original.bin";
        byte[] original = [4, 5, 6];
        File.WriteAllBytes(Path.Combine(export, file), original);
        Directory.CreateDirectory(Path.Combine(export, "empty"));
        using var stop = new CancellationTokenSource();
        await using var server = new SmbServer(new() { RootPath = export, Port = 0, UserName = "user", Password = "password" });
        var run = server.RunAsync(stop.Token);
        try
        {
            await using var client = await SmbClient.ConnectAsync("127.0.0.1", "files", new()
            {
                UserName = "user", Password = "password", Port = server.LocalEndPoint.Port
            });
            (string Operation, Func<Task> Act)[] changes =
            [
                ("overwrite file", () => client.WriteAllBytesAsync(file, new byte[] { 7 })),
                ("delete file", () => client.DeleteAsync(file)),
                ("rename file", () => client.MoveAsync(file, "moved.bin")),
                ("delete directory", () => client.DeleteAsync("empty", true)),
                ("create directory", () => client.CreateDirectoryAsync("new-dir")),
                ("create file", () => client.WriteAllBytesAsync("new-file", ReadOnlyMemory<byte>.Empty))
            ];
            foreach (var change in changes)
                await Check.StatusAsync(NtStatus.AccessDenied, change.Act, $"read-only share: {change.Operation}");
            Check.Bytes(original, await client.ReadAllBytesAsync(file), "read-only file contents");
            var entries = Directory.GetFileSystemEntries(export).Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
            Check.Equal(true, entries.SequenceEqual(new[] { "empty", file }), "read-only share contents");
        }
        finally { stop.Cancel(); await run; }
        Console.WriteLine("PASS read-only share rejects namespace and file mutations and preserves stored data");
    }
}
