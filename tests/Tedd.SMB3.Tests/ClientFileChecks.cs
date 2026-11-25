using Tedd.SMB3;

internal static class ClientFileChecks
{
    internal static async Task RunAsync(string root)
    {
        string export = Directory.CreateDirectory(Path.Combine(root, $"client-files-{Guid.NewGuid():N}")).FullName;
        try
        {
            using var stop = new CancellationTokenSource();
            await using var server = new SmbServer(new()
            {
                RootPath = export, Port = 0, UserName = "reader", Password = "testpass", Writable = true
            });
            var run = server.RunAsync(stop.Token);
            try
            {
                var options = new SmbClientOptions { Port = server.LocalEndPoint.Port, UserName = "reader", Password = "testpass" };
                await using var client = await SmbClient.ConnectAsync("127.0.0.1", "files", options);
                await using var peer = await SmbClient.ConnectAsync("127.0.0.1", "files", options);
                await OpenModesAsync(client, export);
                await TransferBoundariesAsync(client, export);
                await PositionalIoAsync(client, export);
                await DirectoryOperationsAsync(client);
                await AccessAndLifetimeAsync(client);
                await SharedHandlesAsync(client, peer, export);
                await ConcurrentCreationAsync(client, peer, export);
            }
            finally { stop.Cancel(); await run; }
        }
        finally { Directory.Delete(export, true); }
    }

    private static async Task OpenModesAsync(SmbClient client, string export)
    {
        byte[] original = [3, 1, 4];
        const string name = "disposition.bin";
        string path = Path.Combine(export, name);
        foreach (var mode in Enum.GetValues<FileMode>())
        foreach (bool exists in new[] { false, true })
        {
            File.Delete(path);
            if (exists) File.WriteAllBytes(path, original);
            string scenario = $"{mode}, file initially {(exists ? "present" : "absent")}";
            async Task Open()
            {
                await using var file = await client.OpenAsync(name, mode, FileAccess.ReadWrite);
                long expected = exists && mode is FileMode.Open or FileMode.OpenOrCreate ? original.Length : 0;
                Check.Equal(expected, file.Length, scenario);
            }

            if (mode == FileMode.Append)
                await Check.ThrowsAsync<NotSupportedException>(Open, scenario);
            else if (exists && mode == FileMode.CreateNew)
                await Check.StatusAsync(NtStatus.ObjectNameCollision, Open, scenario);
            else if (!exists && mode is FileMode.Open or FileMode.Truncate)
                await Check.StatusAsync(NtStatus.ObjectNameNotFound, Open, scenario);
            else
                await Open();

            bool shouldExist = exists || mode is FileMode.Create or FileMode.CreateNew or FileMode.OpenOrCreate;
            Check.Equal(shouldExist, File.Exists(path), scenario);
            if (shouldExist)
                Check.Bytes(exists && mode is not (FileMode.Create or FileMode.Truncate) ? original : [], File.ReadAllBytes(path), scenario);
        }
        Console.WriteLine("PASS all public file modes against present and absent files");
    }

    private static async Task TransferBoundariesAsync(SmbClient client, string export)
    {
        const int chunk = 65536;
        const string name = "transfer.bin";
        string path = Path.Combine(export, name);
        var random = new Random(1783);
        foreach (int size in new[] { 0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk - 1, 2 * chunk, 2 * chunk + 1, 16 * chunk - 1, 16 * chunk, 16 * chunk + 1 })
        {
            byte[] source = new byte[size + 2];
            random.NextBytes(source);
            await client.WriteAllBytesAsync(name, source.AsMemory(1, size));
            Check.Bytes(source[1..^1], File.ReadAllBytes(path), $"disk after writing {size}");

            // Seed reads through the filesystem so matching client/server errors cannot cancel out.
            random.NextBytes(source);
            byte[] expected = source[1..^1];
            File.WriteAllBytes(path, expected);
            Check.Bytes(expected, await client.ReadAllBytesAsync(name), $"read-all {size}");
            await using var handle = await client.OpenAsync(name);
            byte[] buffer = new byte[chunk + 5];
            Array.Fill(buffer, (byte)0xCA);
            int count = await handle.ReadAsync(buffer.AsMemory(1, chunk + 2), 0);
            Check.Equal(Math.Min(size, chunk + 2), count, $"bounded read {size}");
            byte[] expectedBuffer = Enumerable.Repeat((byte)0xCA, buffer.Length).ToArray();
            expected.AsSpan(0, count).CopyTo(expectedBuffer.AsSpan(1));
            Check.Bytes(expectedBuffer, buffer, $"read slice {size}");
            Check.Equal(0, await handle.ReadAsync(buffer, size), $"EOF at {size}");
            Check.Equal(0, await handle.ReadAsync(buffer, 1L << 32), $"64-bit offset beyond {size}");
        }
        Console.WriteLine("PASS reads and writes around 64 KiB, 128 KiB and 1 MiB, buffer slices and EOF");
        byte[] pattern = new byte[2 * SmbLimits.MaxFileIoSize];
        random.NextBytes(pattern);
        File.WriteAllBytes(path, pattern);
        await using var shared = await client.OpenAsync(name);
        async Task ReadAndVerify(int offset)
        {
            byte[] destination = new byte[SmbLimits.MaxFileIoSize];
            Check.Equal(destination.Length, await shared.ReadAsync(destination, offset), "queued full-size file read");
            Check.Bytes(pattern[offset..(offset + destination.Length)], destination, "queued reads retain independent contents");
        }
        await Task.WhenAll(Enumerable.Range(0, 8).Select(i => ReadAndVerify(i % 2 * SmbLimits.MaxFileIoSize)));
    }

    private static async Task PositionalIoAsync(SmbClient client, string export)
    {
        const string name = "positional.bin";
        using var model = new MemoryStream();
        var random = new Random(19847);
        await using (var handle = await client.OpenAsync(name, FileMode.CreateNew, FileAccess.ReadWrite))
        {
            for (int step = 0; step < 96; step++)
            {
                int offset = random.Next(0, 16385);
                string scenario = $"positional I/O step {step}";
                switch (step % 3)
                {
                    case 0:
                        byte[] data = new byte[random.Next(1, 8193)];
                        random.NextBytes(data);
                        model.Position = offset;
                        model.Write(data);
                        await handle.WriteAsync(data, offset);
                        break;
                    case 1:
                        model.SetLength(offset);
                        await handle.SetLengthAsync(offset);
                        break;
                    default:
                        byte[] expected = new byte[2048];
                        byte[] actual = new byte[expected.Length];
                        model.Position = offset;
                        Check.Equal(model.Read(expected), await handle.ReadAsync(actual, offset), scenario);
                        Check.Bytes(expected, actual, scenario);
                        break;
                }
                Check.Equal(model.Length, handle.Length, scenario);
            }
            await handle.WriteAsync(ReadOnlyMemory<byte>.Empty, model.Length + 99);
            Check.Equal(model.Length, handle.Length, "empty write beyond EOF");
            await handle.FlushAsync();
        }
        Check.Bytes(model.ToArray(), File.ReadAllBytes(Path.Combine(export, name)), "final positional I/O contents");
        Console.WriteLine("PASS deterministic positional reads, writes, truncation and extension against MemoryStream");
    }

    private static async Task DirectoryOperationsAsync(SmbClient client)
    {
        const string dir = "parent";
        const string file = "parent/child";
        await client.CreateDirectoryAsync(dir);
        await client.CreateDirectoryAsync(dir);
        Check.Equal(0, (await client.ListDirectoryAsync(dir)).Count, "empty directory");
        Check.Equal(true, (await client.GetInfoAsync(dir, true)).Attributes.HasFlag(FileAttributes.Directory), "directory attribute");
        await client.WriteAllBytesAsync(file, new byte[] { 7 });
        await Check.StatusAsync(NtStatus.NotADirectory, () => client.ListDirectoryAsync(file), "list regular file");
        await Check.StatusAsync(NtStatus.FileIsADirectory, () => client.ReadAllBytesAsync(dir), "read directory as file");
        await Check.StatusAsync(NtStatus.DirectoryNotEmpty, () => client.DeleteAsync(dir, true), "delete populated directory");
        await Check.StatusAsync(NtStatus.ObjectNameNotFound, () => client.CreateDirectoryAsync("missing/grandchild"), "absent parent");
        Check.Bytes([7], await client.ReadAllBytesAsync(file), "child retained after rejected operations");
        await client.DeleteAsync(file);
        await client.DeleteAsync(dir, true);
        await Check.StatusAsync(NtStatus.ObjectNameNotFound, () => client.ListDirectoryAsync(dir), "deleted directory");
        Console.WriteLine("PASS directory creation, type mismatches, nonempty deletion and missing parents");
    }

    private static async Task AccessAndLifetimeAsync(SmbClient client)
    {
        const string name = "access.bin";
        await client.WriteAllBytesAsync(name, new byte[] { 42 });
        await using (var writer = await client.OpenAsync(name, FileMode.Open, FileAccess.Write))
            await Check.StatusAsync(NtStatus.AccessDenied, () => writer.ReadAsync(new byte[1], 0), "read on write-only handle");
        await using var reader = await client.OpenAsync(name);
        await Check.StatusAsync(NtStatus.AccessDenied, () => reader.WriteAsync(new byte[1], 0), "write on read-only handle");
        await Check.StatusAsync(NtStatus.AccessDenied, () => reader.SetLengthAsync(0), "truncate on read-only handle");
        await Check.StatusAsync(NtStatus.AccessDenied, () => reader.SetMetadataAsync(attributes: FileAttributes.Hidden), "set attributes on read-only handle");
        await Check.ThrowsAsync<ArgumentOutOfRangeException>(() => reader.ReadAsync(Memory<byte>.Empty, -1), "negative read offset");
        await Check.ThrowsAsync<ArgumentOutOfRangeException>(() => reader.WriteAsync(ReadOnlyMemory<byte>.Empty, -1), "negative write offset");
        await Check.ThrowsAsync<ArgumentOutOfRangeException>(() => reader.SetLengthAsync(-1), "negative length");
        await reader.DisposeAsync();
        await Check.ThrowsAsync<ObjectDisposedException>(() => reader.ReadAsync(new byte[1], 0), "read after close");
        await Check.ThrowsAsync<ObjectDisposedException>(() => reader.WriteAsync(new byte[1], 0), "write after close");
        await Check.ThrowsAsync<ObjectDisposedException>(() => reader.SetLengthAsync(1), "truncate after close");
        await Check.ThrowsAsync<ObjectDisposedException>(() => reader.FlushAsync(), "flush after close");
        await Check.ThrowsAsync<ObjectDisposedException>(() => reader.SetMetadataAsync(), "set attributes after close");
        Check.Bytes([42], await client.ReadAllBytesAsync(name), "file preserved after rejected operations");
        Console.WriteLine("PASS handle access rights, negative offsets, repeated close and use after close");
    }

    private static async Task SharedHandlesAsync(SmbClient client, SmbClient peer, string export)
    {
        const string source = "source.bin";
        const string target = "target.bin";
        await client.WriteAllBytesAsync(source, new byte[] { 1 });
        await client.WriteAllBytesAsync(target, new byte[] { 2 });
        await using (var held = await peer.OpenAsync(target))
            await Check.StatusAsync(NtStatus.SharingViolation, () => client.MoveAsync(source, target, true), "replace open destination");
        Check.Bytes([1], await peer.ReadAllBytesAsync(source), "source after rejected replacement");
        Check.Bytes([2], await peer.ReadAllBytesAsync(target), "target after rejected replacement");
        await using (var held = await peer.OpenAsync(source))
        {
            await client.MoveAsync(source, target, true);
            Check.Equal(false, File.Exists(Path.Combine(export, source)), "old name after replace");
            Check.Bytes([1], await client.ReadAllBytesAsync(target), "replacement data");
            await using (var second = await client.OpenAsync(target))
            {
                await peer.DeleteAsync(target);
                await Check.StatusAsync(NtStatus.DeletePending, () => client.GetInfoAsync(target), "new open during pending delete");
                byte[] buffer = new byte[1];
                Check.Equal(1, await held.ReadAsync(buffer, 0), "original handle after rename and pending delete");
                Check.Bytes([1], buffer, "original handle still references source data");
            }
            await Check.StatusAsync(NtStatus.DeletePending, () => peer.GetInfoAsync(target), "pending delete with one remaining handle");
        }
        Check.Equal(false, File.Exists(Path.Combine(export, target)), "last close completes deletion");
        await client.WriteAllBytesAsync(target, new byte[] { 3 });
        Check.Bytes([3], await peer.ReadAllBytesAsync(target), "reuse name after deletion");
        Console.WriteLine("PASS cross-session replacement and pending deletion through the last open handle");
    }

    private static async Task ConcurrentCreationAsync(SmbClient client, SmbClient peer, string export)
    {
        const string name = "exclusive-create.bin";
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task<bool> TryCreate(SmbClient contender, byte marker)
        {
            await start.Task;
            SmbFile file;
            try { file = await contender.OpenAsync(name, FileMode.CreateNew, FileAccess.ReadWrite); }
            catch (SmbException error) when (error.NtStatus == NtStatus.ObjectNameCollision) { return false; }
            await using (file)
                await file.WriteAsync(new byte[] { marker }, 0);
            return true;
        }

        var first = TryCreate(client, 1);
        var second = TryCreate(peer, 2);
        start.SetResult();
        bool[] winners = await Task.WhenAll(first, second);
        Check.Equal(1, winners.Count(won => won), "concurrent CreateNew winner count");
        Check.Bytes([winners[0] ? (byte)1 : (byte)2], File.ReadAllBytes(Path.Combine(export, name)), "concurrent CreateNew winner data");
        Console.WriteLine("PASS concurrent exclusive creation yields one owner and preserves its data");
    }
}
