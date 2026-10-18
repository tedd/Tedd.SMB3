using System.Net;
using Tedd.SMB3;

// Keep hosting policy separate from the library; the password is read from the process environment.
if (args.Length == 0 || args[0] != "serve")
{
    Console.Error.WriteLine("Usage: Tedd.SMB3.Host serve --root PATH [--share files] [--user smbtest] [--bind 127.0.0.1] [--port 445] [--writable] [--allow-unencrypted]\nSet TEDD_SMB_PASSWORD in the process environment.");
    return 2;
}

string Get(string key, string fallback)
{
    int p = Array.IndexOf(args, key);
    return p >= 0 && p + 1 < args.Length ? args[p + 1] : fallback;
}

string password = Environment.GetEnvironmentVariable("TEDD_SMB_PASSWORD") ?? throw new ArgumentException("TEDD_SMB_PASSWORD is required.");
using var stop = new CancellationTokenSource();
// Ctrl+C requests orderly shutdown so active sessions release handles and key material.
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stop.Cancel();
};
await using var server = new SmbServer(new() { RootPath = Get("--root", ""), ShareName = Get("--share", "files"), UserName = Get("--user", "smbtest"), Password = password, ListenAddress = IPAddress.Parse(Get("--bind", "127.0.0.1")), Port = int.Parse(Get("--port", "445")), Writable = args.Contains("--writable"), RequireEncryption = !args.Contains("--allow-unencrypted"), Log = Console.WriteLine });
await server.RunAsync(stop.Token).ConfigureAwait(false);
return 0;
