using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Tedd.Smb;

public sealed record SmbServerOptions
{
    public required string RootPath { get; init; }
    public string ShareName { get; init; } = "files";
    public required string UserName { get; init; }
    public required string Password { get; init; }
    public IPAddress ListenAddress { get; init; } = IPAddress.Loopback;
    public int Port { get; init; } = 445;
    public bool Writable { get; init; }
    public bool RequireEncryption { get; init; } = true;
    public int MaxConnections { get; init; } = 32;
    public Action<string>? Log { get; init; }
}

/// <summary>A bounded SMB 3.1.1 file server with a single configured local account and disk share.</summary>
public sealed class SmbServer : IAsyncDisposable
{
    internal readonly SmbServerOptions Options;
    internal readonly object FileGate = new();
    internal readonly List<OpenFile> OpenFiles = [];
    internal readonly byte[] GuidBytes = Guid.NewGuid().ToByteArray();
    private readonly TcpListener listener;
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentDictionary<long, Task> workers = new();
    private long workerId;
    private bool started;
    public IPEndPoint LocalEndPoint => (IPEndPoint)listener.LocalEndpoint;

    public SmbServer(SmbServerOptions options)
    {
        if (!Directory.Exists(options.RootPath)) throw new DirectoryNotFoundException(options.RootPath);
        if (string.IsNullOrWhiteSpace(options.UserName) || string.IsNullOrEmpty(options.Password) || string.IsNullOrWhiteSpace(options.ShareName) || options.ShareName.IndexOfAny(['\\', '/', ':']) >= 0 || options.ShareName.Equals("IPC$", StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("Invalid account or share configuration.");
        if (options.MaxConnections is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(options));
        Options = options with { RootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(options.RootPath)) };
        if ((File.GetAttributes(Options.RootPath) & FileAttributes.ReparsePoint) != 0) throw new ArgumentException("Export root cannot be a link.");
        listener = new TcpListener(options.ListenAddress, options.Port);
    }
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        if (started) throw new InvalidOperationException("Server already started."); started = true;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(stop.Token, cancellationToken);
        listener.Start(); Options.Log?.Invoke($"Listening on {LocalEndPoint}; share {Options.ShareName}; SMB 3.1.1; encryption required={Options.RequireEncryption}.");
        try
        {
            while (!linked.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(linked.Token);
                if (workers.Count >= Options.MaxConnections) { client.Dispose(); continue; }
                long id = Interlocked.Increment(ref workerId);
                var task = ServeAsync(client, linked.Token); workers[id] = task;
                _ = task.ContinueWith(_ => { workers.TryRemove(id, out var ignored); }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { }
        finally { linked.Cancel(); listener.Stop(); await Task.WhenAll(workers.Values); }
    }
    private async Task ServeAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        using (var connection = new ServerConnection(this))
        {
            try
            {
                client.NoDelay = true; var stream = client.GetStream();
                while (!ct.IsCancellationRequested)
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(connection.Authenticated ? TimeSpan.FromMinutes(15) : TimeSpan.FromSeconds(30));
                    var request = await Wire.ReceiveAsync(stream, timeout.Token);
                    var response = connection.Process(request);
                    if (response.Length != 0) await Wire.SendAsync(stream, response, timeout.Token);
                    if (connection.LoggedOff) break;
                }
            }
            catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or CryptographicException or ArgumentException or OverflowException)
            { Options.Log?.Invoke($"Connection closed: {e.GetType().Name}: {e.Message}"); }
        }
    }
    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync(); listener.Stop(); await Task.WhenAll(workers.Values); stop.Dispose();
    }
}

internal sealed class ServerConnection : IDisposable
{
    private readonly SmbServer server;
    private readonly NtlmServer auth;
    private readonly FileService files;
    private readonly Dictionary<uint, bool> trees = [];
    private readonly HashSet<ulong> credits = [0];
    private ulong nextCredit = 1;
    private uint nextTree;
    private readonly ulong session = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8)) | 1;
    private SessionCrypto? crypto;
    private byte[] preauth = new byte[64];
    private bool negotiated, challenged, rawNtlm;
    private int cipher;
    internal bool Authenticated => crypto != null;
    internal bool LoggedOff { get; private set; }
    internal ServerConnection(SmbServer server) { this.server = server; auth = new(server.Options.UserName, server.Options.Password); files = new(server); }
    internal byte[] Process(byte[] packet)
    {
        if (packet[0] == 0xff) return LegacyNegotiate(packet);
        bool encrypted = packet[0] == 0xfd;
        if (encrypted) packet = (crypto ?? throw new SmbException(Status.AccessDenied)).Decrypt(packet, session);
        Wire.Validate(packet);
        if (Wire.U16(packet, 12) == 12)
        {
            // All operations finish synchronously on this channel. CANCEL has no
            // response and refers to an earlier MessageId, consuming no credit.
            if (!Authenticated || Wire.U64(packet, 40) != session || packet.Length != 68 || Wire.U32(packet, 20) != 0 || Wire.U16(packet, 64) != 4 || (server.Options.RequireEncryption && !encrypted)) throw new SmbException(Status.InvalidParameter);
            if (!encrypted) crypto!.Verify(packet);
            return [];
        }
        var requests = new List<byte[]>(); int p = 0;
        while (true)
        {
            if (requests.Count >= 32) throw new SmbException(Status.InvalidParameter);
            var rest = packet.AsSpan(p); Wire.Validate(rest); uint next = Wire.U32(rest, 20);
            if (next != 0 && (next < 64 || next > rest.Length - 64 || (next & 7) != 0)) throw new SmbException(Status.InvalidParameter);
            var request = rest[..(next == 0 ? rest.Length : checked((int)next))].ToArray();
            if (Wire.U16(request, 6) > 1 || !credits.Remove(Wire.U64(request, 24)) || (Wire.U32(request, 16) & 3) != 0) throw new SmbException(Status.InvalidParameter);
            if (Authenticated && !encrypted) crypto!.Verify(request);
            requests.Add(request); if (next == 0) break; p += (int)next;
        }
        if (requests.Count != 1 && requests.Any(x => Wire.U16(x, 12) <= 1)) throw new SmbException(Status.InvalidParameter);
        var replies = new List<byte[]>(); uint lastTree = 0; bool relatedFailed = false;
        foreach (var original in requests)
        {
            var request = (byte[])original.Clone(); ushort cmd = Wire.U16(request, 12); bool related = (Wire.U32(request, 16) & 4) != 0;
            if (related)
            {
                if (replies.Count == 0) throw new SmbException(Status.InvalidParameter);
                Wire.W64(request, 40, session); Wire.W32(request, 36, lastTree);
            }
            else { relatedFailed = false; files.RelatedId = null; }
            uint status = Status.Success; byte[] body; uint tree = Wire.U32(request, 36);
            if (cmd is 0 or 1) preauth = Negotiation.Hash(preauth, original);
            try
            {
                if (relatedFailed) throw new SmbException(Status.InvalidParameter);
                if (cmd == 0) body = Negotiate(request);
                else if (cmd == 1) body = Setup(request, out status);
                else
                {
                    if (!Authenticated || Wire.U64(request, 40) != session) throw new SmbException(0xc0000203);
                    if (server.Options.RequireEncryption && !encrypted) throw new SmbException(Status.AccessDenied);
                    if (cmd == 3) { body = TreeConnect(request, out tree); }
                    else if (cmd is 2 or 13) { body = new byte[] { 4, 0, 0, 0 }; if (cmd == 2) LoggedOff = true; }
                    else
                    {
                        if (!trees.TryGetValue(tree, out bool pipe)) throw new SmbException(0xc00000c9);
                        if (cmd == 4) { files.CloseTree(tree); trees.Remove(tree); body = new byte[] { 4, 0, 0, 0 }; }
                        else body = files.Dispatch(cmd, request, tree, pipe);
                    }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or OverflowException or NotSupportedException)
            {
                status = MapError(e); body = new byte[9]; Wire.W16(body, 0, 9); relatedFailed = true;
                server.Options.Log?.Invoke($"Command {cmd}: 0x{status:X8} ({e.Message})");
            }
            var response = Wire.Join(Wire.Header(cmd, Wire.U64(request, 24), cmd == 0 ? 0 : session, tree), body);
            Wire.W32(response, 8, status); Wire.W32(response, 16, 1 | (related ? 4u : 0u));
            int grant = Math.Min(Math.Max(1, (int)Wire.U16(request, 14)), 32 - credits.Count);
            for (int i = 0; i < grant; i++) credits.Add(nextCredit++);
            Wire.W16(response, 14, grant); lastTree = tree;
            if (cmd == 0 || (cmd == 1 && status == Status.MoreProcessing)) preauth = Negotiation.Hash(preauth, response);
            replies.Add(response);
        }
        for (int i = 0; i < replies.Count; i++)
        {
            var r = replies[i];
            if (i < replies.Count - 1) { Array.Resize(ref r, Wire.Align(r.Length)); Wire.W32(r, 20, (uint)r.Length); replies[i] = r; }
            if (Authenticated && !encrypted) crypto!.Sign(r);
        }
        var result = Wire.Join(replies.ToArray()); return encrypted ? crypto!.Encrypt(result, session) : result;
    }
    private byte[] LegacyNegotiate(byte[] request)
    {
        if (negotiated || challenged || request.Length < 35 || request[4] != 0x72 || !request.AsSpan(0, 4).SequenceEqual(new byte[] { 0xff, 0x53, 0x4d, 0x42 }) || request[32] != 0 || Wire.U16(request, 33) != request.Length - 35 || request.AsSpan(35).IndexOf(Encoding.ASCII.GetBytes("SMB 2.???\0")) < 0)
            throw new SmbException(Status.NotSupported);
        var b = Wire.Join(Wire.Header(0, 0), new byte[64], Spnego.Initial);
        Wire.W32(b, 16, 1); Wire.W16(b, 14, 1); Wire.W16(b, 64, 65); Wire.W16(b, 66, 3); Wire.W16(b, 68, 0x2ff);
        server.GuidBytes.CopyTo(b, 72); Wire.W32(b, 92, 65536); Wire.W32(b, 96, 65536); Wire.W32(b, 100, 65536); Wire.W64(b, 104, (ulong)DateTime.UtcNow.ToFileTimeUtc()); Wire.W16(b, 120, 128); Wire.W16(b, 122, Spnego.Initial.Length);
        credits.Clear(); credits.Add(1); nextCredit = 2; return b;
    }
    private byte[] Negotiate(byte[] request)
    {
        if (negotiated || request.Length < 102 || Wire.U16(request, 64) != 36) throw new SmbException(Status.InvalidParameter);
        int count = Wire.U16(request, 66); var dialects = Wire.Slice(request, 100, checked(count * 2)); bool found = false;
        for (int i = 0; i < count; i++) if (Wire.U16(dialects, i * 2) == 0x311) found = true;
        if (!found) throw new SmbException(Status.NotSupported);
        int offset = checked((int)Wire.U32(request, 92)); if (offset < Wire.Align(100 + count * 2)) throw new SmbException(Status.InvalidParameter);
        var algorithms = Negotiation.ValidateContexts(request, offset, Wire.U16(request, 96), false);
        bool signing = algorithms.Signing; cipher = algorithms.Cipher;
        int ctxOffset = Wire.Align(128 + Spnego.Initial.Length);
        var b = new byte[ctxOffset - 64]; Wire.W16(b, 0, 65); Wire.W16(b, 2, 3); Wire.W16(b, 4, 0x311); Wire.W16(b, 6, signing ? 3 : 2);
        server.GuidBytes.CopyTo(b, 8); Wire.W32(b, 24, 0x40); Wire.W32(b, 28, 65536); Wire.W32(b, 32, 65536); Wire.W32(b, 36, 65536);
        Wire.W64(b, 40, (ulong)DateTime.UtcNow.ToFileTimeUtc()); Wire.W16(b, 56, 128); Wire.W16(b, 58, Spnego.Initial.Length); Wire.W32(b, 60, (uint)ctxOffset); Spnego.Initial.CopyTo(b, 64);
        negotiated = true; return Wire.Join(b, Negotiation.Contexts(signing, cipher));
    }
    private byte[] Setup(byte[] request, out uint status)
    {
        if (!negotiated || Authenticated || request.Length < 88 || Wire.U16(request, 64) != 25 || request[66] != 0 || Wire.U64(request, 80) != 0 || Wire.U64(request, 40) != (challenged ? session : 0)) throw new SmbException(Status.InvalidParameter);
        int o = Wire.U16(request, 76), n = Wire.U16(request, 78); if (o < 88 || n > 16384) throw new SmbException(Status.InvalidParameter);
        var input = Wire.Slice(request, o, n).ToArray();
        if (!challenged) rawNtlm = input.AsSpan().StartsWith("NTLMSSP\0"u8);
        var token = Spnego.Unwrap(input); byte[] output;
        if (!challenged) { var challenge = auth.Challenge(token); output = rawNtlm ? challenge : Spnego.Response(challenge, true); challenged = true; status = Status.MoreProcessing; }
        else
        {
            var key = auth.Authenticate(token);
            try { crypto = new SessionCrypto(key, preauth, true, cipher); }
            finally { CryptographicOperations.ZeroMemory(key); }
            output = rawNtlm ? [] : Spnego.Response([], false); status = Status.Success;
        }
        var b = new byte[8]; Wire.W16(b, 0, 9); Wire.W16(b, 2, Authenticated && server.Options.RequireEncryption ? 4 : 0); Wire.W16(b, 4, 72); Wire.W16(b, 6, output.Length); return Wire.Join(b, output);
    }
    private byte[] TreeConnect(byte[] request, out uint id)
    {
        if (request.Length < 72 || Wire.U16(request, 64) != 9) throw new SmbException(Status.InvalidParameter);
        var path = Wire.Text(Wire.Slice(request, Wire.U16(request, 68), Wire.U16(request, 70))).Split('\\');
        if (path.Length != 4 || path[0] != "" || path[1] != "" || path[2].Length == 0) throw new SmbException(Status.BadNetworkName);
        bool pipe = path[3].Equals("IPC$", StringComparison.OrdinalIgnoreCase);
        if (!pipe && !path[3].Equals(server.Options.ShareName, StringComparison.OrdinalIgnoreCase)) throw new SmbException(Status.BadNetworkName);
        if (trees.Count >= 64) throw new SmbException(Status.BufferTooSmall);
        id = ++nextTree; trees.Add(id, pipe);
        var b = new byte[16]; Wire.W16(b, 0, 16); b[2] = pipe ? (byte)2 : (byte)1; Wire.W32(b, 4, 0x30 | (server.Options.RequireEncryption ? 0x8000u : 0)); Wire.W32(b, 12, server.Options.Writable ? 0x001f01ffu : 0x001200a9u); return b;
    }
    internal static uint MapError(Exception e) => e switch
    {
        SmbException smb => smb.NtStatus,
        FileNotFoundException or DirectoryNotFoundException => Status.NotFound,
        UnauthorizedAccessException => Status.AccessDenied,
        ArgumentException or OverflowException => Status.InvalidParameter,
        NotSupportedException => Status.NotSupported,
        IOException io when (io.HResult & 0xffff) == 32 => Status.SharingViolation,
        _ => Status.AccessDenied
    };
    public void Dispose() { files.Dispose(); crypto?.Dispose(); }
}
