using Tedd.SMB3;

internal static class ProviderChecks
{
    internal static async Task RunAsync(string root)
    {
        // This provider has no filesystem path, FileStream, or native handle.
        var memory = new MemoryProvider();
        var other = new MemoryProvider();
        using var stop = new CancellationTokenSource();
        await using var server = new SmbServer(new()
        {
            Shares = [new("memory", memory) { Writable = true }, new("other", other) { Writable = true },
                new("readonly", memory), new("disk", SmbDirectoryProvider.Create(root)) { Writable = true }],
            UserName = "smbtest", Password = "testpass", Port = 0
        });
        var run = server.RunAsync(stop.Token);
        SmbClientOptions options = new() { UserName = "smbtest", Password = "testpass", Port = server.LocalEndPoint.Port };
        try
        {
            await using var client = await SmbClient.ConnectAsync("127.0.0.1", "MeMoRy", options);
            await using var isolated = await SmbClient.ConnectAsync("127.0.0.1", "other", options);
            await using var readOnly = await SmbClient.ConnectAsync("127.0.0.1", "readonly", options);
            await using var disk = await SmbClient.ConnectAsync("127.0.0.1", "disk", options);
            await client.CreateDirectoryAsync("folder");
            await client.WriteAllBytesAsync("folder/data.bin", new byte[] { 1, 2, 3, 4 });
            await isolated.WriteAllBytesAsync("folder", new byte[] { 9 });
            await disk.WriteAllBytesAsync("provider-disk.bin", new byte[] { 7 });
            if (!client.IsCompressionEnabled) throw new Exception("LZNT1 compression was not negotiated.");
            byte[] zeros = new byte[65536];
            await client.WriteAllBytesAsync("compressed.bin", zeros);
            if (!(await client.ReadAllBytesAsync("compressed.bin")).AsSpan().SequenceEqual(zeros))
                throw new Exception("Compressed SMB provider transfer failed.");
            await client.DeleteAsync("compressed.bin");
            await using (var uncompressed = await SmbClient.ConnectAsync("127.0.0.1", "memory", options with { EnableCompression = false }))
            {
                if (uncompressed.IsCompressionEnabled) throw new Exception("Client compression opt-out ignored.");
                _ = await uncompressed.ListDirectoryAsync();
            }
            if (!(await client.ReadAllBytesAsync("folder/data.bin")).AsSpan().SequenceEqual(new byte[] { 1, 2, 3, 4 }) ||
                (await client.ListDirectoryAsync("folder")).Single().Name != "data.bin" ||
                (await isolated.ReadAllBytesAsync("folder"))[0] != 9)
                throw new Exception("Provider dispatch or share isolation failed.");
            var time = new DateTime(2001, 2, 3, 4, 5, 6, DateTimeKind.Utc);
            await using (var handle = await client.OpenAsync("folder/data.bin", FileMode.Open, FileAccess.ReadWrite))
            {
                await handle.SetLengthAsync(12);
                await handle.WriteAsync(new byte[] { 5, 6 }, 8);
                await handle.FlushAsync();
                await handle.SetMetadataAsync(creationUtc: time, attributes: FileAttributes.Hidden);
            }
            await client.MoveAsync("folder/data.bin", "folder/moved.bin");
            var info = await client.GetInfoAsync("folder/moved.bin");
            if (info.Length != 12 || info.CreationTimeUtc != time || info.Attributes != FileAttributes.Hidden ||
                (await client.ReadAllBytesAsync("folder/moved.bin"))[8] != 5)
                throw new Exception("Provider metadata or offset I/O failed.");
            await Denied(() => readOnly.WriteAllBytesAsync("forbidden", new byte[] { 1 }), NtStatus.AccessDenied);
            await Denied(() => client.WriteAllBytesAsync("../outside", new byte[] { 1 }), NtStatus.AccessDenied);
            await using (var handle = await client.OpenAsync("folder/moved.bin", FileMode.Open, FileAccess.Read, FileShare.None))
                await Denied(async () => { await using var blocked = await readOnly.OpenAsync("folder/moved.bin"); }, NtStatus.SharingViolation);
            await client.DeleteAsync("folder/moved.bin");
            await client.DeleteAsync("folder", true);
            await disk.DeleteAsync("provider-disk.bin");
            await Denied(async () => { await using var missing = await SmbClient.ConnectAsync("127.0.0.1", "absent", options); }, NtStatus.BadNetworkName);
            Console.WriteLine("PASS virtual provider positional I/O, metadata, rename, deletion, multiple shares, read-only aliases and isolation");
        }
        finally { stop.Cancel(); await run; }
        try
        {
            await using var invalid = new SmbServer(new()
            {
                Shares = [new("same", memory), new("SAME", other)], UserName = "x", Password = "y"
            });
            throw new Exception("Duplicate shares accepted.");
        }
        catch (ArgumentException) { }
        var authentication = new NtlmAuthentication("smbtest", "testpass");
        try
        {
            await using var invalid = new SmbServer(new() { Shares = [new("denied", memory)], AuthenticationProvider = authentication });
            throw new Exception("External authentication accepted without a share authorizer.");
        }
        catch (ArgumentException) { }
        using var policyStop = new CancellationTokenSource();
        await using var policyServer = new SmbServer(new()
        {
            Shares = [new("denied", memory) { Authorize = _ => false }, new("allowed", memory) { Authorize = _ => true }],
            AuthenticationProvider = authentication, Port = 0, EnableCompression = false
        });
        var policyRun = policyServer.RunAsync(policyStop.Token);
        try
        {
            var policyOptions = options with { Port = policyServer.LocalEndPoint.Port };
            await Denied(async () => { await using var denied = await SmbClient.ConnectAsync("127.0.0.1", "denied", policyOptions); }, NtStatus.AccessDenied);
            await using var allowed = await SmbClient.ConnectAsync("127.0.0.1", "allowed", policyOptions);
            if (allowed.IsCompressionEnabled) throw new Exception("Server compression opt-out ignored.");
            _ = await allowed.ListDirectoryAsync();
            Console.WriteLine("PASS external authentication requires share authorization; client/server compression opt-outs");
        }
        finally { policyStop.Cancel(); await policyRun; }
    }

    private static async Task Denied(Func<Task> action, uint status)
    {
        try { await action(); } catch (SmbException e) when (e.NtStatus == status) { return; }
        throw new Exception($"Expected SMB status {status:X8}.");
    }

    private sealed class MemoryProvider : ISmbShareProvider
    {
        private sealed class Node(ulong id, bool directory)
        {
            internal byte[] Data = [];
            internal SmbFileMetadata Metadata = new(id, 0, directory ? FileAttributes.Directory : FileAttributes.Normal,
                DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow, DateTime.UtcNow);
        }
        private readonly Dictionary<string, Node> nodes = new(StringComparer.OrdinalIgnoreCase) { [""] = new(1, true) };
        private ulong nextId = 1;
        public SmbVolumeInfo Volume { get; } = new(Guid.NewGuid(), DateTime.UtcNow, 1048576, 524288, 524288, "Memory");
        public string ResolvePath(string path) => nodes.Keys.FirstOrDefault(x => x.Equals(path, StringComparison.OrdinalIgnoreCase)) ?? path;
        public SmbFileMetadata? GetMetadata(string path) => nodes.TryGetValue(path, out var node) ? node.Metadata with { Length = node.Data.Length } : null;
        public IEnumerable<string> EnumerateDirectory(string path) => nodes.Keys.Where(x => x.Length != 0 &&
            (x.Contains('/') ? x[..x.LastIndexOf('/')] : "").Equals(path, StringComparison.OrdinalIgnoreCase)).ToArray();
        public ISmbFile OpenFile(string path, FileMode mode, FileAccess access, FileShare share, bool writeThrough)
        {
            if (!nodes.TryGetValue(path, out var node))
            {
                if (mode == FileMode.Open) throw new FileNotFoundException();
                nodes.Add(path, node = new(++nextId, false));
            }
            else if (mode == FileMode.CreateNew) throw new SmbException(NtStatus.ObjectNameCollision);
            if (mode == FileMode.Truncate) node.Data = [];
            return new MemoryFile(node);
        }
        public void CreateDirectory(string path) => nodes.Add(path, new(++nextId, true));
        public void Delete(string path, bool directory) => nodes.Remove(path);
        public void Move(string source, string destination, bool directory, bool replace)
        {
            if (!replace && nodes.ContainsKey(destination)) throw new SmbException(NtStatus.ObjectNameCollision);
            var node = nodes[source]; nodes.Remove(source); nodes[destination] = node;
        }
        public void SetMetadata(string path, SmbMetadataUpdate update)
        {
            var node = nodes[path];
            node.Metadata = node.Metadata with
            {
                CreationTimeUtc = update.CreationTimeUtc ?? node.Metadata.CreationTimeUtc,
                LastAccessTimeUtc = update.LastAccessTimeUtc ?? node.Metadata.LastAccessTimeUtc,
                LastWriteTimeUtc = update.LastWriteTimeUtc ?? node.Metadata.LastWriteTimeUtc,
                ChangeTimeUtc = update.ChangeTimeUtc ?? node.Metadata.ChangeTimeUtc,
                Attributes = update.Attributes ?? node.Metadata.Attributes
            };
        }
        public void MarkChanged(string path, bool archive) { }
        private sealed class MemoryFile(Node node) : ISmbFile
        {
            public long Length => node.Data.Length;
            public ValueTask<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int count = (int)Math.Max(0, Math.Min(buffer.Length, node.Data.LongLength - offset));
                if (count != 0) node.Data.AsMemory(checked((int)offset), count).CopyTo(buffer);
                return ValueTask.FromResult(count);
            }
            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, long offset, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (offset + buffer.Length > node.Data.LongLength) SetLength(offset + buffer.Length);
                buffer.CopyTo(node.Data.AsMemory(checked((int)offset)));
                return ValueTask.CompletedTask;
            }
            public void SetLength(long length) => Array.Resize(ref node.Data, checked((int)length));
            public void Flush() { }
            public void Dispose() { }
        }
    }
}
