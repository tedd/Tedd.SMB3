using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Tedd.Smb;

public sealed record SmbClientOptions
{
    public required string UserName { get; init; }
    public required string Password { get; init; }
    public string Domain { get; init; } = "WORKGROUP";
    public int Port { get; init; } = 445;
    public bool Encrypt { get; init; } = true;
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

public sealed record SmbEntry(string Name, long Length, FileAttributes Attributes, DateTime CreationTimeUtc, DateTime LastWriteTimeUtc)
{
    public DateTime LastAccessTimeUtc { get; init; }
    public DateTime ChangeTimeUtc { get; init; }
}

/// <summary>A single-session SMB 3.1.1 client. Requests on a connection are serialized.</summary>
public sealed class SmbClient : IAsyncDisposable
{
    private readonly TcpClient tcp = new();
    private readonly SemaphoreSlim gate = new(1);
    private readonly SmbClientOptions options;
    private NetworkStream stream = null!;
    private SessionCrypto? crypto;
    private ulong message, session;
    private int credits = 1;
    private uint tree;
    private bool encrypted, disposed, failed;
    public string Dialect => "3.1.1";
    public bool IsEncrypted => encrypted;
    private SmbClient(SmbClientOptions options) => this.options = options;

    public static async Task<SmbClient> ConnectAsync(string host, string share, SmbClientOptions options, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host); ArgumentException.ThrowIfNullOrWhiteSpace(share);
        var client = new SmbClient(options);
        try { await client.ConnectCore(host, share, ct); return client; }
        catch { await client.DisposeAsync(); throw; }
    }
    private async Task ConnectCore(string host, string share, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(options.RequestTimeout); ct = timeout.Token;
        await tcp.ConnectAsync(host, options.Port, ct); tcp.NoDelay = true; stream = tcp.GetStream();
        var body = new byte[40]; Wire.W16(body, 0, 36); Wire.W16(body, 2, 1); Wire.W16(body, 4, 3); Wire.W32(body, 8, 0x40); Guid.NewGuid().ToByteArray().CopyTo(body, 12); Wire.W32(body, 28, 104); Wire.W16(body, 32, 3); Wire.W16(body, 36, 0x311);
        var negotiate = Packet(0, Wire.Join(body, Negotiation.Contexts(offerBoth: true)));
        var response = await Raw(negotiate, ct); Check(response);
        if (response.Length < 128 || Wire.U16(response, 64) != 65 || Wire.U16(response, 68) != 0x311 || (Wire.U16(response, 66) & 1) == 0) throw new SmbException(Status.NotSupported);
        var algorithms = Negotiation.ValidateContexts(response, checked((int)Wire.U32(response, 124)), Wire.U16(response, 70), true);
        byte[] hash = Negotiation.Hash(Negotiation.Hash(new byte[64], negotiate), response);
        var ntlm = Ntlm.Negotiate(); var setup = Packet(1, SetupBody(ntlm));
        hash = Negotiation.Hash(hash, setup); response = await Raw(setup, ct);
        if (Wire.U32(response, 8) != Status.MoreProcessing || response.Length < 72 || Wire.U16(response, 64) != 9) throw new SmbException(Wire.U32(response, 8));
        session = Wire.U64(response, 40); if (session == 0) throw new SmbException(Status.LogonFailure);
        hash = Negotiation.Hash(hash, response);
        var challenge = Spnego.Unwrap(Wire.Slice(response, Wire.U16(response, 68), Wire.U16(response, 70)).ToArray());
        var (token, key) = Ntlm.Authenticate(ntlm, challenge, options.UserName, options.Password, options.Domain);
        try
        {
            setup = Packet(1, SetupBody(token)); hash = Negotiation.Hash(hash, setup); response = await Raw(setup, ct); Check(response);
            if (response.Length < 72 || Wire.U16(response, 64) != 9 || Wire.U64(response, 40) != session || (Wire.U16(response, 66) & 3) != 0) throw new SmbException(Status.LogonFailure);
            crypto = new SessionCrypto(key, hash, false, algorithms.Cipher); crypto.Verify(response); encrypted = options.Encrypt || (Wire.U16(response, 66) & 4) != 0;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
        var path = Encoding.Unicode.GetBytes($"\\\\{host}\\{share}"); body = new byte[8]; Wire.W16(body, 0, 9); Wire.W16(body, 4, 72); Wire.W16(body, 6, path.Length);
        response = await Exchange(3, Wire.Join(body, path), ct); tree = Wire.U32(response, 36);
        if (tree == 0 || response.Length < 80 || response[66] != 1) throw new SmbException(Status.BadNetworkName);
        encrypted |= (Wire.U32(response, 68) & 0x8000) != 0;
    }
    private static byte[] SetupBody(byte[] token)
    {
        var b = new byte[24]; Wire.W16(b, 0, 25); b[3] = 3; Wire.W16(b, 12, 88); Wire.W16(b, 14, token.Length); return Wire.Join(b, token);
    }
    private byte[] Packet(ushort cmd, byte[] body)
    {
        if (credits < 1) throw new SmbException(Status.InvalidParameter);
        credits--; return Wire.Join(Wire.Header(cmd, message++, session, tree), body);
    }
    private async Task<byte[]> Raw(byte[] packet, CancellationToken ct)
    {
        await Wire.SendAsync(stream, packet, ct); var r = await Wire.ReceiveAsync(stream, ct); Wire.Validate(r);
        if (Wire.U64(r, 24) != Wire.U64(packet, 24) || Wire.U16(r, 12) != Wire.U16(packet, 12) || Wire.U32(r, 20) != 0 || (Wire.U32(r, 16) & 3) != 1) throw new SmbException(Status.InvalidParameter);
        credits = checked(credits + Wire.U16(r, 14));
        return r;
    }
    private static void Check(byte[] r) { uint status = Wire.U32(r, 8); if (status != 0) throw new SmbException(status); }
    private async Task<byte[]> Exchange(ushort cmd, byte[] body, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(disposed, this); if (failed) throw new IOException("SMB connection is no longer usable.");
        await gate.WaitAsync(ct);
        bool responseTrusted = false;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct); timeout.CancelAfter(options.RequestTimeout);
            var p = Packet(cmd, body); if (!encrypted) crypto!.Sign(p);
            await Wire.SendAsync(stream, encrypted ? crypto!.Encrypt(p, session) : p, timeout.Token);
            var r = await Wire.ReceiveAsync(stream, timeout.Token); bool wasEncrypted = r[0] == 0xfd;
            if (wasEncrypted) r = crypto!.Decrypt(r, session);
            else if (encrypted) throw new SmbException(Status.AccessDenied);
            else crypto!.Verify(r);
            Wire.Validate(r);
            if (Wire.U64(r, 24) != Wire.U64(p, 24) || Wire.U16(r, 12) != cmd || Wire.U64(r, 40) != session || Wire.U32(r, 20) != 0 || (Wire.U32(r, 16) & 3) != 1) throw new SmbException(Status.InvalidParameter);
            responseTrusted = true;
            credits = checked(credits + Wire.U16(r, 14));
            Check(r); return r;
        }
        catch (Exception e) when (e is OperationCanceledException or EndOfStreamException or CryptographicException or SocketException || e is SmbException && !responseTrusted) { failed = true; tcp.Dispose(); throw; }
        finally { gate.Release(); }
    }
    public async Task<SmbFile> OpenAsync(string path, FileMode mode = FileMode.Open, FileAccess access = FileAccess.Read, FileShare share = FileShare.ReadWrite | FileShare.Delete, CancellationToken ct = default)
        => await OpenCore(path, mode, access, share, false, ct);
    private async Task<SmbFile> OpenCore(string path, FileMode mode, FileAccess access, FileShare share, bool directory, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(path); var name = Encoding.Unicode.GetBytes(path.Replace('/', '\\')); var b = new byte[56]; Wire.W16(b, 0, 57); Wire.W32(b, 4, 2);
        uint desired = (access & FileAccess.Read) != 0 ? 0x120089u : 0;
        if ((access & FileAccess.Write) != 0) desired |= 0x130116;
        Wire.W32(b, 24, desired); Wire.W32(b, 28, directory ? 0x10u : 0x80); Wire.W32(b, 32, (uint)share);
        Wire.W32(b, 36, mode switch { FileMode.CreateNew => 2, FileMode.Create => 5, FileMode.Open => 1, FileMode.OpenOrCreate => 3, FileMode.Truncate => 4, _ => throw new NotSupportedException("Append mode is not supported; use an explicit offset.") });
        Wire.W32(b, 40, directory ? 1u : 0x40); Wire.W16(b, 44, 120); Wire.W16(b, 46, name.Length);
        var r = await Exchange(5, Wire.Join(b, name), ct); if (r.Length < 152 || Wire.U16(r, 64) != 89) throw new SmbException(Status.InvalidParameter);
        return new SmbFile(this, r[128..144], checked((long)Wire.U64(r, 112)));
    }
    internal async Task<int> ReadAsync(byte[] id, Memory<byte> buffer, long offset, CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset); int n = Math.Min(buffer.Length, 65536); if (n == 0) return 0;
        var b = new byte[49]; Wire.W16(b, 0, 49); Wire.W32(b, 4, (uint)n); Wire.W64(b, 8, (ulong)offset); id.CopyTo(b, 16);
        try
        {
            var r = await Exchange(8, b, ct); int length = checked((int)Wire.U32(r, 68)); if (length > n) throw new SmbException(Status.InvalidParameter);
            Wire.Slice(r, r[66], length).CopyTo(buffer.Span); return length;
        }
        catch (SmbException e) when (e.NtStatus == Status.EndOfFile) { return 0; }
    }
    internal async Task WriteAsync(byte[] id, ReadOnlyMemory<byte> data, long offset, CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        while (data.Length > 0)
        {
            int n = Math.Min(data.Length, 65536); var b = new byte[48 + n]; Wire.W16(b, 0, 49); Wire.W16(b, 2, 112); Wire.W32(b, 4, (uint)n); Wire.W64(b, 8, checked((ulong)offset)); id.CopyTo(b, 16); data.Span[..n].CopyTo(b.AsSpan(48));
            var r = await Exchange(9, b, ct); int written = checked((int)Wire.U32(r, 68)); if (written < 1 || written > n) throw new IOException("Invalid SMB write count."); offset = checked(offset + written); data = data[written..];
        }
    }
    internal async Task CloseAsync(byte[] id, CancellationToken ct)
    { var b = new byte[24]; Wire.W16(b, 0, 24); id.CopyTo(b, 8); _ = await Exchange(6, b, ct); }
    internal async Task FlushAsync(byte[] id, CancellationToken ct)
    { var b = new byte[24]; Wire.W16(b, 0, 24); id.CopyTo(b, 8); _ = await Exchange(7, b, ct); }
    internal async Task SetAsync(byte[] id, int cls, byte[] data, CancellationToken ct)
    { var b = new byte[32]; Wire.W16(b, 0, 33); b[2] = 1; b[3] = (byte)cls; Wire.W32(b, 4, (uint)data.Length); Wire.W16(b, 8, 96); id.CopyTo(b, 16); _ = await Exchange(17, Wire.Join(b, data), ct); }
    public async Task<SmbEntry> GetInfoAsync(string path, bool directory = false, CancellationToken ct = default)
    {
        await using var file = await OpenCore(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, directory, ct);
        var b = new byte[40]; Wire.W16(b, 0, 41); b[2] = 1; b[3] = 34; Wire.W32(b, 4, 56); file.Id.CopyTo(b, 24);
        var r = await Exchange(16, b, ct); var data = Wire.Slice(r, Wire.U16(r, 66), checked((int)Wire.U32(r, 68)));
        return new(path, checked((long)Wire.U64(data, 40)), (FileAttributes)Wire.U32(data, 48), DateTime.FromFileTimeUtc(checked((long)Wire.U64(data, 0))), DateTime.FromFileTimeUtc(checked((long)Wire.U64(data, 16))))
        { LastAccessTimeUtc = DateTime.FromFileTimeUtc(checked((long)Wire.U64(data, 8))), ChangeTimeUtc = DateTime.FromFileTimeUtc(checked((long)Wire.U64(data, 24))) };
    }
    public async Task<byte[]> ReadAllBytesAsync(string path, CancellationToken ct = default)
    {
        await using var file = await OpenAsync(path, ct: ct); if (file.Length > int.MaxValue) throw new IOException("File exceeds byte-array capacity; use OpenAsync.");
        using var result = new MemoryStream(); var buffer = new byte[65536]; int n;
        while ((n = await file.ReadAsync(buffer, result.Length, ct)) > 0) { if (result.Length + n > int.MaxValue) throw new IOException("File exceeds byte-array capacity."); result.Write(buffer, 0, n); }
        return result.ToArray();
    }
    public async Task WriteAllBytesAsync(string path, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    { await using var f = await OpenAsync(path, FileMode.Create, FileAccess.ReadWrite, ct: ct); await f.WriteAsync(data, 0, ct); await f.FlushAsync(ct); }
    public async Task CreateDirectoryAsync(string path, CancellationToken ct = default)
    { await using var f = await OpenCore(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, true, ct); }
    public async Task DeleteAsync(string path, bool directory = false, CancellationToken ct = default)
    { await using var f = await OpenCore(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, directory, ct); await SetAsync(f.Id, 13, [1], ct); }
    public async Task MoveAsync(string source, string destination, bool replace = false, CancellationToken ct = default)
    {
        await using var f = await OpenAsync(source, FileMode.Open, FileAccess.ReadWrite, ct: ct); var name = Encoding.Unicode.GetBytes(destination.Replace('/', '\\')); var b = new byte[20]; b[0] = replace ? (byte)1 : (byte)0; Wire.W32(b, 16, (uint)name.Length); await SetAsync(f.Id, 10, Wire.Join(b, name), ct);
    }
    public async Task<IReadOnlyList<SmbEntry>> ListDirectoryAsync(string path = "", CancellationToken ct = default)
    {
        await using var f = await OpenCore(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, true, ct); var results = new List<SmbEntry>(); bool first = true;
        while (true)
        {
            var b = new byte[34]; Wire.W16(b, 0, 33); b[2] = 37; b[3] = first ? (byte)1 : (byte)0; f.Id.CopyTo(b, 8); Wire.W16(b, 24, 96); Wire.W16(b, 26, 2); Wire.W32(b, 28, 65536); b[32] = (byte)'*'; first = false;
            byte[] r; try { r = await Exchange(14, b, ct); } catch (SmbException e) when (e.NtStatus == Status.NoMoreFiles) { break; }
            int o = Wire.U16(r, 66), n = checked((int)Wire.U32(r, 68)); var data = Wire.Slice(r, o, n).ToArray(); int p = 0;
            while (true)
            {
                var entry = Wire.Slice(data, p, data.Length - p); if (entry.Length < 104) throw new SmbException(Status.InvalidParameter);
                string name = Wire.Text(Wire.Slice(entry, 104, checked((int)Wire.U32(entry, 60))));
                if (name is not ("." or "..")) results.Add(new(name, checked((long)Wire.U64(entry, 40)), (FileAttributes)Wire.U32(entry, 56), DateTime.FromFileTimeUtc(checked((long)Wire.U64(entry, 8))), DateTime.FromFileTimeUtc(checked((long)Wire.U64(entry, 24)))));
                int next = checked((int)Wire.U32(entry, 0)); if (next == 0) break; if (next < 104 || next > entry.Length || (next & 7) != 0) throw new SmbException(Status.InvalidParameter); p += next;
            }
        }
        return results;
    }
    public async ValueTask DisposeAsync()
    {
        if (disposed) return;
        try { if (crypto != null && !failed && tcp.Connected) { try { _ = await Exchange(2, [4, 0, 0, 0], CancellationToken.None); } catch (IOException) { } catch (OperationCanceledException) { } } }
        finally { disposed = true; crypto?.Dispose(); tcp.Dispose(); gate.Dispose(); }
    }
}

public sealed class SmbFile : IAsyncDisposable
{
    private readonly SmbClient client;
    internal byte[] Id { get; }
    private bool disposed;
    public long Length { get; private set; }
    internal SmbFile(SmbClient client, byte[] id, long length) { this.client = client; Id = id; Length = length; }
    public Task<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken ct = default) { ObjectDisposedException.ThrowIf(disposed, this); return client.ReadAsync(Id, buffer, offset, ct); }
    public async Task WriteAsync(ReadOnlyMemory<byte> data, long offset, CancellationToken ct = default) { ObjectDisposedException.ThrowIf(disposed, this); await client.WriteAsync(Id, data, offset, ct); Length = Math.Max(Length, checked(offset + data.Length)); }
    public Task FlushAsync(CancellationToken ct = default) { ObjectDisposedException.ThrowIf(disposed, this); return client.FlushAsync(Id, ct); }
    public async Task SetLengthAsync(long length, CancellationToken ct = default)
    { ObjectDisposedException.ThrowIf(disposed, this); ArgumentOutOfRangeException.ThrowIfNegative(length); var b = new byte[8]; Wire.W64(b, 0, (ulong)length); await client.SetAsync(Id, 20, b, ct); Length = length; }
    public Task SetMetadataAsync(DateTime? creationUtc = null, DateTime? accessUtc = null, DateTime? writeUtc = null, DateTime? changeUtc = null, FileAttributes? attributes = null, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this); var b = new byte[40]; var times = new[] { creationUtc, accessUtc, writeUtc, changeUtc };
        for (int i = 0; i < times.Length; i++) if (times[i] is { } time) Wire.W64(b, i * 8, checked((ulong)time.ToFileTimeUtc()));
        if (attributes is { } value) Wire.W32(b, 32, (uint)value); return client.SetAsync(Id, 4, b, ct);
    }
    public async ValueTask DisposeAsync() { if (disposed) return; disposed = true; await client.CloseAsync(Id, CancellationToken.None); }
}
