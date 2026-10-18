using System.Net;
using Tedd.SMB3;

// Keep hosting policy separate from the library; the password is read from the process environment.
if (args.Length == 0 || args[0] != "serve")
{
    Console.Error.WriteLine("Usage: Tedd.SMB3.Host serve --root PATH [--share files] [--user smbtest] [--bind 127.0.0.1] [--port 445] [--writable] [--allow-unencrypted]\nNTLM: set TEDD_SMB_PASSWORD. Kerberos: --kerberos-principal cifs/hostname@REALM --user allowed-principal [--keytab PATH on Linux].");
    return 2;
}

string Get(string key, string fallback)
{
    int p = Array.IndexOf(args, key);
    return p >= 0 && p + 1 < args.Length ? args[p + 1] : fallback;
}

string servicePrincipal = Get("--kerberos-principal", "");
string password = servicePrincipal.Length != 0 ? "" : Environment.GetEnvironmentVariable("TEDD_SMB_PASSWORD") ?? throw new ArgumentException("TEDD_SMB_PASSWORD is required.");
string user = Get("--user", "smbtest");
if (servicePrincipal.Length != 0 && !args.Contains("--user")) throw new ArgumentException("Kerberos requires an explicit --user allowed-principal.");
ISmbAuthenticationProvider? authentication = servicePrincipal.Length == 0 ? null : new SmbKerberosAuthentication(servicePrincipal, args.Contains("--keytab") ? Get("--keytab", "") : null);
using var stop = new CancellationTokenSource();
// Ctrl+C requests orderly shutdown so active sessions release handles and key material.
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stop.Cancel();
};
await using var server = new SmbServer(new()
{
    Shares = [new(Get("--share", "files"), SmbDirectoryProvider.Create(Get("--root", "")))
    {
        Writable = args.Contains("--writable"),
        Authorize = principal => principal.Equals(user, StringComparison.OrdinalIgnoreCase)
    }],
    AuthenticationProvider = authentication, UserName = user, Password = password,
    ListenAddress = IPAddress.Parse(Get("--bind", "127.0.0.1")), Port = int.Parse(Get("--port", "445")),
    RequireEncryption = !args.Contains("--allow-unencrypted"), Log = Console.WriteLine
});
await server.RunAsync(stop.Token).ConfigureAwait(false);
return 0;
