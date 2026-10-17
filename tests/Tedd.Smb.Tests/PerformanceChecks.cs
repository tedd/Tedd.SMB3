using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;
using Tedd.Smb;

/// <summary>Repeatable kernel measurements; file and network throughput are tested separately.</summary>
internal static class PerformanceChecks
{
    internal static void Run(string? selectedOperation = null, int? selectedSize = null)
    {
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            Runtime = RuntimeInformation.FrameworkDescription,
            OS = RuntimeInformation.OSDescription,
            Architecture = RuntimeInformation.ProcessArchitecture.ToString(),
            ProcessorCount = Environment.ProcessorCount,
            ServerGC = System.Runtime.GCSettings.IsServerGC,
            TieredCompilation = Environment.GetEnvironmentVariable("DOTNET_TieredCompilation") ?? "runtime-default",
            TieredPGO = Environment.GetEnvironmentVariable("DOTNET_TieredPGO") ?? "runtime-default"
        }));

        // Fixed work and warmup budgets are shared by baseline and candidate builds.
        foreach (int size in new[] { 64, 4096, 65536 })
        {
            if (selectedSize.HasValue && selectedSize.Value != size) continue;
            byte[] packet = new byte[size];
            Wire.Header(13, 1, 42).CopyTo(packet, 0);
            using var sender = new SessionCrypto(new byte[16], new byte[64], false);
            using var receiver = new SessionCrypto(new byte[16], new byte[64], true);
            if (selectedOperation is null or "sign-verify") Measure("sign-verify", size, size == 65536 ? 100 : 1000, () =>
            {
                sender.Sign(packet);
                receiver.Verify(packet);
            });
            if (selectedOperation is null or "encrypt-decrypt") Measure("encrypt-decrypt", size, size == 65536 ? 100 : 1000, () =>
            {
                byte[] encrypted = sender.Encrypt(packet, 42);
                byte[] decrypted = receiver.Decrypt(encrypted, 42);
                if (!packet.AsSpan().SequenceEqual(decrypted)) throw new Exception("Encryption changed plaintext.");
            });
        }
    }

    private static void Measure(string operation, int bytes, int iterations, Action action)
    {
        // Allocation counters cover this synchronous kernel, with setup excluded.
        for (int i = 0; i < 100; i++) action();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        long started = Stopwatch.GetTimestamp();
        for (int i = 0; i < iterations; i++) action();
        double elapsed = Stopwatch.GetElapsedTime(started).TotalNanoseconds;
        long allocation = GC.GetAllocatedBytesForCurrentThread() - allocated;
        Console.WriteLine(JsonSerializer.Serialize(new
        {
            Operation = operation,
            Bytes = bytes,
            Iterations = iterations,
            NanosecondsPerOperation = elapsed / iterations,
            AllocatedBytesPerOperation = (double)allocation / iterations
        }));
    }
}
