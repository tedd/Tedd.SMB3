using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using Tedd.SMB3;

internal static class BulkTransferChecks
{
    // Each worker owns one session. Timed intervals include creates and closes.
    internal static async Task RunAsync(string[] args)
    {
        if (args.Length != 8 || args[1] is not ("rdma" or "tcp"))
            throw new ArgumentException("bulk <rdma|tcp> <host> <port> <share> <sessions> <files-per-session> <MiB-per-file>");
        int sessions = int.Parse(args[5]), count = int.Parse(args[6]);
        long size = checked(long.Parse(args[7]) * 1024 * 1024);
        if (sessions is < 1 or > 32 || count < 1 || size <= 0) throw new ArgumentOutOfRangeException(nameof(args));
        long total = checked(sessions * (long)count * size);
        var options = new SmbClientOptions
        {
            UseSmbDirect = args[1] == "rdma", Port = int.Parse(args[3]), Encrypt = true, EnableCompression = false,
            UserName = Environment.GetEnvironmentVariable("TEDD_SMB_USER") ?? "smbtest",
            Password = Environment.GetEnvironmentVariable("TEDD_SMB_PASSWORD") ?? throw new ArgumentException("Set TEDD_SMB_PASSWORD."),
            Domain = Environment.GetEnvironmentVariable("TEDD_SMB_DOMAIN") ?? "WORKGROUP"
        };
        string prefix = $"bulk-{Guid.NewGuid():N}";
        var clients = new List<SmbClient>();
        var files = Enumerable.Range(0, sessions).Select(_ => new List<string>()).ToArray();
        var blocks = Enumerable.Range(0, sessions).Select(_ => RandomNumberGenerator.GetBytes(1024 * 1024)).ToArray();

        void MarkBlock(int worker, int index, long blockOffset)
        {
            BinaryPrimitives.WriteInt32LittleEndian(blocks[worker], index);
            BinaryPrimitives.WriteInt64LittleEndian(blocks[worker].AsSpan(4), blockOffset);
        }

        async Task WriteFiles(int worker)
        {
            for (int index = 0; index < count; index++)
            {
                string name = $"{prefix}-{worker}-{index}.bin";
                await using var file = await clients[worker].OpenAsync(name, FileMode.CreateNew, FileAccess.Write);
                files[worker].Add(name);
                for (long offset = 0; offset < size; offset += blocks[worker].Length)
                {
                    MarkBlock(worker, index, offset);
                    await file.WriteAsync(blocks[worker], offset);
                }
            }
        }

        async Task ReadFiles(int worker, bool verify)
        {
            byte[] buffer = new byte[blocks[worker].Length];
            for (int index = 0; index < files[worker].Count; index++)
            {
                string name = files[worker][index];
                await using var file = await clients[worker].OpenAsync(name, FileMode.Open, FileAccess.Read);
                Check.Equal(size, file.Length, "bulk file length");
                long offset = 0;
                while (offset < size)
                {
                    int start = (int)(offset % blocks[worker].Length);
                    if (verify && start == 0) MarkBlock(worker, index, offset);
                    int limit = Math.Min(blocks[worker].Length - start, buffer.Length);
                    int n = await file.ReadAsync(buffer.AsMemory(0, limit), offset);
                    if (n <= 0 || (verify && !buffer.AsSpan(0, n).SequenceEqual(blocks[worker].AsSpan(start, n))))
                        throw new IOException($"Invalid data at {name} offset {offset}.");
                    offset += n;
                }
            }
        }

        async Task<double> Measure(Func<int,Task> run)
        {
            var clock = Stopwatch.StartNew();
            await Task.WhenAll(Enumerable.Range(0, sessions).Select(run));
            return total / clock.Elapsed.TotalSeconds / 1e9;
        }

        try
        {
            for (int i = 0; i < sessions; i++)
                clients.Add(await SmbClient.ConnectAsync(args[2], args[4], options));
            double writes = await Measure(WriteFiles);
            double reads = await Measure(i => ReadFiles(i, false));
            await Task.WhenAll(Enumerable.Range(0, sessions).Select(i => ReadFiles(i, true)));
            Console.WriteLine($"{args[1]} encrypted, {sessions} sessions, {count} files/session, {size} bytes/file. Write {writes:F3} GB/s, read {reads:F3} GB/s. Contents verified.");
        }
        finally
        {
            try
            {
                for (int i = 0; i < clients.Count; i++)
                    foreach (string name in files[i]) await clients[i].DeleteAsync(name);
            }
            finally
            {
                foreach (var client in clients) await client.DisposeAsync();
            }
        }
    }
}
