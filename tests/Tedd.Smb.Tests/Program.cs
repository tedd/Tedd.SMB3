using System.Net;
using System.Security.Cryptography;
using System.Text;
using Tedd.Smb;

void Equal(byte[] expected, byte[] actual, string label) { if (!expected.AsSpan().SequenceEqual(actual)) throw new Exception(label); Console.WriteLine($"PASS {label}"); }
void Hex(string expected, byte[] actual, string label) => Equal(Convert.FromHexString(expected), actual, label);
async Task Reject(Func<Task> action, uint status, string label)
{
    try { await action(); } catch (SmbException e) when (e.NtStatus == status) { Console.WriteLine($"PASS {label}"); return; }
    throw new Exception($"Expected rejection: {label}");
}
async Task RoundTrip(string host, int port, string share, bool encrypt, string user, string password, string domain)
{
    await using var client = await SmbClient.ConnectAsync(host, share, new() { UserName = user, Password = password, Domain = domain, Port = port, Encrypt = encrypt });
    if (client.IsEncrypted != encrypt) throw new Exception("Unexpected encryption state.");
    string dir = "interop-" + Guid.NewGuid().ToString("N");
    var data = RandomNumberGenerator.GetBytes(262267); string original = dir + "/unicode-æøå-文件.bin", moved = dir + "/renamed.bin";
    await client.CreateDirectoryAsync(dir);
    try
    {
        await client.WriteAllBytesAsync(original, data); Equal(data, await client.ReadAllBytesAsync(original), "multi-frame Unicode round trip");
        var entries = await client.ListDirectoryAsync(dir); if (entries.Count != 1 || entries[0].Length != data.Length) throw new Exception("Directory metadata mismatch."); Console.WriteLine("PASS directory metadata");
        await client.MoveAsync(original, moved); await Reject(() => client.ReadAllBytesAsync(original), Status.NotFound, "rename removes old name");
        await using (var f = await client.OpenAsync(moved, FileMode.Open, FileAccess.ReadWrite))
        { await f.SetLengthAsync(17); await f.WriteAsync(new byte[] { 11, 12 }, 3); await f.FlushAsync(); }
        var small = data[..17]; small[3] = 11; small[4] = 12; Equal(small, await client.ReadAllBytesAsync(moved), "truncate and offset write");
        await client.DeleteAsync(moved); Console.WriteLine($"PASS {host}:{port} SMB {client.Dialect} encrypted={client.IsEncrypted}");
    }
    finally
    {
        foreach (var name in new[] { original, moved })
            try { await client.DeleteAsync(name); } catch (SmbException e) when (e.NtStatus == Status.NotFound) { }
        await client.DeleteAsync(dir, true);
    }
}

if (args.Length > 0 && args[0] == "client")
{
    await RoundTrip(args[1], int.Parse(args[2]), args[3], bool.Parse(args[4]), Environment.GetEnvironmentVariable("TEDD_SMB_USER") ?? "smbtest", Environment.GetEnvironmentVariable("TEDD_SMB_PASSWORD") ?? throw new ArgumentException("Password required."), Environment.GetEnvironmentVariable("TEDD_SMB_DOMAIN") ?? "WORKGROUP");
    return;
}
if (args.Length != 1 || !Path.IsPathFullyQualified(args[0])) throw new ArgumentException("Supply a dedicated absolute fixture directory under the task workspace.");
string root = args[0]; Directory.CreateDirectory(root);
ProtocolChecks.Run(root);
Hex("31D6CFE0D16AE931B73C59D7E0C089C0", Crypto.Md4([]), "RFC1320 MD4 empty");
Hex("A448017AAF21D8525FC10AE87AA6729D", Crypto.Md4(Encoding.ASCII.GetBytes("abc")), "RFC1320 MD4 abc");
Hex("A4F49C406510BDCAB6824EE7C30FD852", Crypto.Md4(Encoding.Unicode.GetBytes("Password")), "NT hash");
var cmacKey = Convert.FromHexString("2B7E151628AED2A6ABF7158809CF4F3C");
Hex("BB1D6929E95937287FA37D129B756746", Crypto.Cmac(cmacKey, []), "NIST CMAC empty");
Hex("070A16B46B4D4144F79BDD9DD04A287C", Crypto.Cmac(cmacKey, Convert.FromHexString("6BC1BEE22E409F96E93D7E117393172A")), "NIST CMAC full block");
Hex("BBF316E8D940AF0AD3", Crypto.Rc4(Encoding.ASCII.GetBytes("Key"), Encoding.ASCII.GetBytes("Plaintext")), "RC4 key exchange vector");
using (var sender = new SessionCrypto(new byte[16], new byte[64], false))
using (var receiver = new SessionCrypto(new byte[16], new byte[64], true))
{
    var packet = Wire.Header(13, 1, 42); var encrypted = sender.Encrypt(packet, 42); Equal(packet, receiver.Decrypt(encrypted, 42), "AES-GCM transform");
    encrypted[^1] ^= 1; try { receiver.Decrypt(encrypted, 42); throw new Exception("Tampering accepted."); } catch (CryptographicException) { Console.WriteLine("PASS GCM tamper rejection"); }
    sender.Sign(packet); receiver.Verify(packet); packet[24] ^= 1; try { receiver.Verify(packet); throw new Exception("Tampering accepted."); } catch (SmbException) { Console.WriteLine("PASS signature tamper rejection"); }
}
foreach (bool encrypt in new[] { false, true })
{
    using var stop = new CancellationTokenSource();
    await using var server = new SmbServer(new() { RootPath = root, UserName = "smbtest", Password = "testpass", Port = 0, Writable = true, RequireEncryption = encrypt });
    var run = server.RunAsync(stop.Token);
    try
    {
        await RoundTrip("127.0.0.1", server.LocalEndPoint.Port, "files", encrypt, "smbtest", "testpass", "WORKGROUP");
        await Reject(async () => { await using var bad = await SmbClient.ConnectAsync("127.0.0.1", "files", new() { UserName = "smbtest", Password = "wrong", Port = server.LocalEndPoint.Port }); }, Status.LogonFailure, "incorrect password");
        await using var client = await SmbClient.ConnectAsync("127.0.0.1", "files", new() { UserName = "smbtest", Password = "testpass", Port = server.LocalEndPoint.Port, Encrypt = encrypt });
        await Reject(() => client.WriteAllBytesAsync("../outside", new byte[1]), Status.AccessDenied, "path traversal");
        await client.WriteAllBytesAsync("sharing.bin", new byte[] { 1, 2, 3 });
        await using (var held = await client.OpenAsync("sharing.bin", FileMode.Open, FileAccess.Read, FileShare.None))
        { await Reject(async () => { await using var blocked = await client.OpenAsync("sharing.bin"); }, Status.SharingViolation, "share access conflict"); }
        await client.DeleteAsync("sharing.bin");
    }
    finally { stop.Cancel(); await run; }
}
using (var stop = new CancellationTokenSource())
{
    string readable = Path.Combine(root, "read-only.bin"); File.WriteAllBytes(readable, new byte[] { 1, 2, 3 });
    await using var server = new SmbServer(new() { RootPath = root, UserName = "smbtest", Password = "testpass", Port = 0 });
    var run = server.RunAsync(stop.Token);
    try
    {
        await using var client = await SmbClient.ConnectAsync("127.0.0.1", "files", new() { UserName = "smbtest", Password = "testpass", Port = server.LocalEndPoint.Port });
        Equal(new byte[] { 1, 2, 3 }, await client.ReadAllBytesAsync("read-only.bin"), "read-only export read");
        await Reject(() => client.WriteAllBytesAsync("forbidden.bin", new byte[1]), Status.AccessDenied, "read-only export denies mutation");
        if (OperatingSystem.IsLinux())
        {
            string link = Path.Combine(root, "escape-link"); File.CreateSymbolicLink(link, "/etc/passwd");
            try { await Reject(() => client.ReadAllBytesAsync("escape-link"), Status.AccessDenied, "symlink escape denied"); } finally { File.Delete(link); }
        }
    }
    finally { stop.Cancel(); await run; File.Delete(readable); }
}
using (var stop = new CancellationTokenSource())
{
    await using var server = new SmbServer(new() { RootPath = root, UserName = "smbtest", Password = "testpass", Port = 0, Writable = true });
    var run = server.RunAsync(stop.Token);
    try
    {
        await using var client = await SmbClient.ConnectAsync("127.0.0.1", "files", new() { UserName = "smbtest", Password = "testpass", Port = server.LocalEndPoint.Port });
        string folder = "pagination-" + Guid.NewGuid().ToString("N"); Directory.CreateDirectory(Path.Combine(root, folder));
        try
        {
            for (int i = 0; i < 400; i++) File.WriteAllBytes(Path.Combine(root, folder, i.ToString("D4") + new string('x', 80)), []);
            if ((await client.ListDirectoryAsync(folder)).Count != 400) throw new Exception("Directory pagination lost entries."); Console.WriteLine("PASS multi-response directory pagination");
        }
        finally { Directory.Delete(Path.Combine(root, folder), true); }
        string file = "metadata-" + Guid.NewGuid().ToString("N"); await client.WriteAllBytesAsync(file, new byte[] { 9 });
        try
        {
            var time = new DateTime(2001, 2, 3, 4, 5, 6, DateTimeKind.Utc).AddTicks(1234000);
            await using (var opened = await client.OpenAsync(file, FileMode.Open, FileAccess.ReadWrite))
                await opened.SetMetadataAsync(creationUtc: time, writeUtc: time, changeUtc: time, attributes: FileAttributes.Hidden | FileAttributes.Archive);
            await client.MoveAsync(file, file + "-renamed"); file += "-renamed";
            var info = await client.GetInfoAsync(file);
            if (info.CreationTimeUtc != time || info.LastWriteTimeUtc != time || (info.Attributes & FileAttributes.Hidden) == 0) throw new Exception("Persistent metadata mismatch.");
            Console.WriteLine("PASS persistent creation/write time and hidden/archive attributes across close and rename");
        }
        catch (SmbException e) when (OperatingSystem.IsLinux() && e.NtStatus == Status.NotSupported) { Console.WriteLine("SKIP exact logical timestamps: backing filesystem does not support user xattrs"); }
        finally { await client.DeleteAsync(file); }
    }
    finally { stop.Cancel(); await run; }
}
Console.WriteLine("ALL TESTS PASSED");
