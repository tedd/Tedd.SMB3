using System.Buffers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Tedd.Smb;

/// <summary>Credentials, transport endpoint, and protection policy for one client session.</summary>
public sealed record SmbClientOptions
{
    public required string UserName { get; init; }
    public required string Password { get; init; }
    public string Domain { get; init; } = "WORKGROUP";
    public int Port { get; init; } = SmbLimits.DefaultPort;
    /// <summary>Requests encryption; a peer may additionally require it at session or share level.</summary>
    public bool Encrypt { get; init; } = true;
    /// <summary>Bounds each exchange after it acquires the connection gate.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>A snapshot of a remote file's name, size, attributes, and UTC timestamps.</summary>
public sealed record SmbEntry(string Name, long Length, FileAttributes Attributes, DateTime CreationTimeUtc, DateTime LastWriteTimeUtc)
{
    public DateTime LastAccessTimeUtc { get; init; }
    public DateTime ChangeTimeUtc { get; init; }
}

/// <summary>A single-session SMB 3.1.1 client. Requests on a connection are serialized.</summary>
public sealed class SmbClient : IAsyncDisposable
{
    private readonly TcpClient tcp = new();
    // A complete request/reply owns the channel, message credits and crypto providers.
    private readonly SemaphoreSlim gate = new(1);
    private readonly SmbClientOptions options;
    private SmbTransport transport = null!;
    private SessionCrypto? crypto;
    private ulong message;
    private ulong session;
    private int credits = 1;
    private uint tree;
    private bool encrypted;
    private bool disposed;
    private bool failed;
    public string Dialect => "3.1.1";
    public bool IsEncrypted => encrypted;

    private SmbClient(SmbClientOptions options) => this.options = options;
    /// <summary>Negotiates SMB 3.1.1, authenticates with NTLMv2, and connects a disk share.</summary>
    public static async Task<SmbClient> ConnectAsync(string host, string share, SmbClientOptions options, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(share);
        var client = new SmbClient(options);
        try
        {
            await client.ConnectCoreAsync(host, share, ct).ConfigureAwait(false);
            return client;
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task ConnectCoreAsync(string host, string share, CancellationToken ct)
    {
        // Only NEGOTIATE and SESSION_SETUP enter the preauthentication transcript.
        // The final setup response is verified using keys bound to that transcript.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(options.RequestTimeout);
        ct = timeout.Token;
        await tcp.ConnectAsync(host, options.Port, ct).ConfigureAwait(false);
        tcp.NoDelay = true;
        transport = new SmbTransport(tcp.GetStream());
        var body = new byte[Wire.Align(Smb2NegotiateRequest.FixedSize + sizeof(ushort))];
        Wire.WriteUInt16LittleEndian(body, 0, Smb2NegotiateRequest.StructureSize);
        Wire.WriteUInt16LittleEndian(body, Smb2NegotiateRequest.DialectCountOffset, 1);
        Wire.WriteUInt16LittleEndian(body, Smb2NegotiateRequest.SecurityModeOffset, Smb2SecurityMode.SigningEnabledAndRequired);
        Wire.WriteUInt32LittleEndian(body, Smb2NegotiateRequest.CapabilitiesOffset, Smb2GlobalCapabilities.Encryption);
        Guid.NewGuid().TryWriteBytes(body.AsSpan(Smb2NegotiateRequest.ClientGuidOffset, 16));
        Wire.WriteUInt32LittleEndian(body, Smb2NegotiateRequest.NegotiateContextOffsetFieldOffset, (uint)(Smb2Header.Size + body.Length));
        Wire.WriteUInt16LittleEndian(body, Smb2NegotiateRequest.NegotiateContextCountOffset, Negotiation.ContextCountWithSigning);
        Wire.WriteUInt16LittleEndian(body, Smb2NegotiateRequest.DialectsOffset, Smb2Dialect.Smb311);
        var negotiate = CreateRequest(Smb2Command.Negotiate, Wire.Join(body, Negotiation.Contexts(offerBoth: true)));
        var response = await ExchangeUnauthenticatedAsync(negotiate, ct).ConfigureAwait(false);
        ThrowIfFailed(response);
        if (response.Length < Smb2Header.Size + Smb2NegotiateResponse.FixedSize || Wire.ReadUInt16LittleEndian(response, Smb2Header.Size) != Smb2NegotiateResponse.StructureSize || Wire.ReadUInt16LittleEndian(response, Smb2Header.Size + Smb2NegotiateResponse.DialectRevisionOffset) != Smb2Dialect.Smb311 || (Wire.ReadUInt16LittleEndian(response, Smb2Header.Size + Smb2NegotiateResponse.SecurityModeOffset) & Smb2SecurityMode.SigningEnabled) == 0)
            throw new SmbException(NtStatus.NotSupported);
        var algorithms = Negotiation.ValidateContexts(response, checked((int)Wire.ReadUInt32LittleEndian(response, Smb2Header.Size + Smb2NegotiateResponse.NegotiateContextOffsetFieldOffset)), Wire.ReadUInt16LittleEndian(response, Smb2Header.Size + Smb2NegotiateResponse.NegotiateContextCountOffset), true);
        byte[] hash = Negotiation.Hash(Negotiation.Hash(new byte[Smb3Cryptography.PreauthHashSize], negotiate), response);
        var ntlm = Ntlm.Negotiate();
        var setup = CreateRequest(Smb2Command.SessionSetup, CreateSessionSetupBody(ntlm));
        hash = Negotiation.Hash(hash, setup);
        response = await ExchangeUnauthenticatedAsync(setup, ct).ConfigureAwait(false);
        if (Wire.ReadUInt32LittleEndian(response, Smb2Header.StatusOffset) != NtStatus.MoreProcessingRequired || response.Length < Smb2Header.Size + Smb2SessionSetupResponse.FixedSize || Wire.ReadUInt16LittleEndian(response, Smb2Header.Size) != Smb2SessionSetupResponse.StructureSize)
            throw new SmbException(Wire.ReadUInt32LittleEndian(response, Smb2Header.StatusOffset));
        session = Wire.ReadUInt64LittleEndian(response, Smb2Header.SessionIdOffset);
        if (session == 0)
            throw new SmbException(NtStatus.LogonFailure);
        hash = Negotiation.Hash(hash, response);
        var challenge = Spnego.Unwrap(Wire.Slice(response, Wire.ReadUInt16LittleEndian(response, Smb2Header.Size + Smb2SessionSetupResponse.SecurityBufferOffsetFieldOffset), Wire.ReadUInt16LittleEndian(response, Smb2Header.Size + Smb2SessionSetupResponse.SecurityBufferLengthOffset)).ToArray());
        var (token, key) = Ntlm.Authenticate(ntlm, challenge, options.UserName, options.Password, options.Domain);
        try
        {
            setup = CreateRequest(Smb2Command.SessionSetup, CreateSessionSetupBody(token));
            hash = Negotiation.Hash(hash, setup);
            response = await ExchangeUnauthenticatedAsync(setup, ct).ConfigureAwait(false);
            ThrowIfFailed(response);
            if (response.Length < Smb2Header.Size + Smb2SessionSetupResponse.FixedSize || Wire.ReadUInt16LittleEndian(response, Smb2Header.Size) != Smb2SessionSetupResponse.StructureSize || Wire.ReadUInt64LittleEndian(response, Smb2Header.SessionIdOffset) != session || (Wire.ReadUInt16LittleEndian(response, Smb2Header.Size + Smb2SessionSetupResponse.SessionFlagsOffset) & (Smb2SessionFlags.IsGuest | Smb2SessionFlags.IsNull)) != 0)
                throw new SmbException(NtStatus.LogonFailure);
            crypto = new SessionCrypto(key, hash, false, algorithms.Cipher);
            crypto.Verify(response);
            encrypted = options.Encrypt || (Wire.ReadUInt16LittleEndian(response, Smb2Header.Size + Smb2SessionSetupResponse.SessionFlagsOffset) & Smb2SessionFlags.EncryptData) != 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        var path = Encoding.Unicode.GetBytes($"\\\\{host}\\{share}");
        body = new byte[Smb2TreeConnectRequest.FixedSize];
        Wire.WriteUInt16LittleEndian(body, 0, Smb2TreeConnectRequest.StructureSize);
        Wire.WriteUInt16LittleEndian(body, Smb2TreeConnectRequest.PathOffsetFieldOffset, Smb2Header.Size + Smb2TreeConnectRequest.FixedSize);
        Wire.WriteUInt16LittleEndian(body, Smb2TreeConnectRequest.PathLengthOffset, path.Length);
        response = await ExchangeAsync(Smb2Command.TreeConnect, Wire.Join(body, path), ct).ConfigureAwait(false);
        tree = Wire.ReadUInt32LittleEndian(response, Smb2Header.TreeIdOffset);
        if (tree == 0 || response.Length < Smb2Header.Size + Smb2TreeConnectResponse.FixedSize || response[Smb2Header.Size + Smb2TreeConnectResponse.ShareTypeOffset] != Smb2ShareType.Disk)
            throw new SmbException(NtStatus.BadNetworkName);
        encrypted |= (Wire.ReadUInt32LittleEndian(response, Smb2Header.Size + Smb2TreeConnectResponse.ShareFlagsOffset) & Smb2ShareFlags.EncryptData) != 0;
    }

    private static byte[] CreateSessionSetupBody(byte[] token)
    {
        var b = new byte[Smb2SessionSetupRequest.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb2SessionSetupRequest.StructureSize);
        b[Smb2SessionSetupRequest.SecurityModeOffset] = (byte)Smb2SecurityMode.SigningEnabledAndRequired;
        Wire.WriteUInt16LittleEndian(b, Smb2SessionSetupRequest.SecurityBufferOffsetFieldOffset, Smb2Header.Size + Smb2SessionSetupRequest.FixedSize);
        Wire.WriteUInt16LittleEndian(b, Smb2SessionSetupRequest.SecurityBufferLengthOffset, token.Length);
        return Wire.Join(b, token);
    }

    private byte[] CreateRequest(ushort cmd, byte[] body)
    {
        if (credits < 1)
            throw new SmbException(NtStatus.InvalidParameter);
        credits--;
        return Wire.Packet(cmd, message++, session, tree, body);
    }

    private async Task<byte[]> ExchangeUnauthenticatedAsync(byte[] packet, CancellationToken ct)
    {
        await transport.SendAsync(packet, ct).ConfigureAwait(false);
        var r = await transport.ReceiveAsync(ct).ConfigureAwait(false);
        Wire.Validate(r);
        if (Wire.ReadUInt64LittleEndian(r, Smb2Header.MessageIdOffset) != Wire.ReadUInt64LittleEndian(packet, Smb2Header.MessageIdOffset) || Wire.ReadUInt16LittleEndian(r, Smb2Header.CommandOffset) != Wire.ReadUInt16LittleEndian(packet, Smb2Header.CommandOffset) || Wire.ReadUInt32LittleEndian(r, Smb2Header.NextCommandOffset) != 0 || (Wire.ReadUInt32LittleEndian(r, Smb2Header.FlagsOffset) & Smb2HeaderFlags.ResponseOrAsync) != Smb2HeaderFlags.ServerToRedir)
            throw new SmbException(NtStatus.InvalidParameter);
        credits = checked(credits + Wire.ReadUInt16LittleEndian(r, Smb2Header.CreditsOffset));
        return r;
    }

    private static void ThrowIfFailed(byte[] r)
    {
        uint status = Wire.ReadUInt32LittleEndian(r, Smb2Header.StatusOffset);
        if (status != 0)
            throw new SmbException(status);
    }

    private async Task<byte[]> ExchangeAsync(ushort cmd, byte[] body, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (failed)
            throw new IOException("SMB connection is no longer usable.");
        await gate.WaitAsync(ct).ConfigureAwait(false);
        bool responseTrusted = false;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(options.RequestTimeout);
            var p = CreateRequest(cmd, body);
            if (!encrypted)
                crypto!.Sign(p);
            await transport.SendAsync(encrypted ? crypto!.Encrypt(p, session) : p, timeout.Token).ConfigureAwait(false);
            var r = await transport.ReceiveAsync(timeout.Token).ConfigureAwait(false);
            bool wasEncrypted = r[Smb2Header.ProtocolIdOffset] == Smb2TransformHeader.ProtocolPrefix;
            if (wasEncrypted)
                r = crypto!.Decrypt(r, session);
            else if (encrypted)
                throw new SmbException(NtStatus.AccessDenied);
            else
                crypto!.Verify(r);
            Wire.Validate(r);
            if (Wire.ReadUInt64LittleEndian(r, Smb2Header.MessageIdOffset) != Wire.ReadUInt64LittleEndian(p, Smb2Header.MessageIdOffset) || Wire.ReadUInt16LittleEndian(r, Smb2Header.CommandOffset) != cmd || Wire.ReadUInt64LittleEndian(r, Smb2Header.SessionIdOffset) != session || Wire.ReadUInt32LittleEndian(r, Smb2Header.NextCommandOffset) != 0 || (Wire.ReadUInt32LittleEndian(r, Smb2Header.FlagsOffset) & Smb2HeaderFlags.ResponseOrAsync) != Smb2HeaderFlags.ServerToRedir)
                throw new SmbException(NtStatus.InvalidParameter);
            responseTrusted = true;
            credits = checked(credits + Wire.ReadUInt16LittleEndian(r, Smb2Header.CreditsOffset));
            ThrowIfFailed(r);
            return r;
        }
        // An interrupted or untrusted exchange leaves framing/credits indeterminate.
        // Abort the transport so queued callers cannot reuse that channel state.
        catch (Exception e) when (e is OperationCanceledException or EndOfStreamException or CryptographicException or SocketException || e is SmbException && !responseTrusted)
        {
            failed = true;
            tcp.Dispose();
            throw;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Opens a share-relative file; append mode requires explicit-offset writes instead.</summary>
    public Task<SmbFile> OpenAsync(string path, FileMode mode = FileMode.Open, FileAccess access = FileAccess.Read, FileShare share = FileShare.ReadWrite | FileShare.Delete, CancellationToken ct = default) => OpenCoreAsync(path, mode, access, share, false, ct);
    private async Task<SmbFile> OpenCoreAsync(string path, FileMode mode, FileAccess access, FileShare share, bool directory, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(path);
        var name = Encoding.Unicode.GetBytes(path.Replace('/', '\\'));
        var b = new byte[Smb2CreateRequest.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb2CreateRequest.StructureSize);
        Wire.WriteUInt32LittleEndian(b, Smb2CreateRequest.ImpersonationLevelOffset, Smb2ImpersonationLevel.Impersonation);
        uint desired = (access & FileAccess.Read) != 0 ? FileAccessMask.FileGenericRead : 0;
        if ((access & FileAccess.Write) != 0)
            desired |= FileAccessMask.FileGenericWrite | FileAccessMask.Delete;
        Wire.WriteUInt32LittleEndian(b, Smb2CreateRequest.DesiredAccessOffset, desired);
        Wire.WriteUInt32LittleEndian(b, Smb2CreateRequest.FileAttributesOffset, directory ? FileAttributeFlags.Directory : FileAttributeFlags.Normal);
        Wire.WriteUInt32LittleEndian(b, Smb2CreateRequest.ShareAccessOffset, (uint)share);
        Wire.WriteUInt32LittleEndian(b, Smb2CreateRequest.CreateDispositionOffset, mode switch
        {
            FileMode.CreateNew => Smb2CreateDisposition.Create,
            FileMode.Create => Smb2CreateDisposition.OverwriteIf,
            FileMode.Open => Smb2CreateDisposition.Open,
            FileMode.OpenOrCreate => Smb2CreateDisposition.OpenIf,
            FileMode.Truncate => Smb2CreateDisposition.Overwrite,
            _ => throw new NotSupportedException("Append mode is not supported; use an explicit offset.")
        });
        Wire.WriteUInt32LittleEndian(b, Smb2CreateRequest.CreateOptionsOffset, directory ? Smb2CreateOptions.DirectoryFile : Smb2CreateOptions.NonDirectoryFile);
        Wire.WriteUInt16LittleEndian(b, Smb2CreateRequest.NameOffsetFieldOffset, Smb2Header.Size + Smb2CreateRequest.FixedSize);
        Wire.WriteUInt16LittleEndian(b, Smb2CreateRequest.NameLengthOffset, name.Length);
        var r = await ExchangeAsync(Smb2Command.Create, Wire.Join(b, name), ct).ConfigureAwait(false);
        if (r.Length < Smb2Header.Size + Smb2CreateResponse.FixedSize || Wire.ReadUInt16LittleEndian(r, Smb2Header.Size) != Smb2CreateResponse.StructureSize)
            throw new SmbException(NtStatus.InvalidParameter);
        return new SmbFile(this, r[(Smb2Header.Size + Smb2CreateResponse.FileIdOffset)..(Smb2Header.Size + Smb2CreateResponse.FileIdOffset + Smb2FileId.Size)], checked((long)Wire.ReadUInt64LittleEndian(r, Smb2Header.Size + Smb2CreateResponse.EndOfFileOffset)));
    }

    internal async Task<int> ReadAsync(byte[] id, Memory<byte> buffer, long offset, CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        int n = Math.Min(buffer.Length, SmbLimits.MaxTransferSize);
        if (n == 0)
            return 0;
        var b = new byte[Smb2ReadRequest.StructureSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb2ReadRequest.StructureSize);
        Wire.WriteUInt32LittleEndian(b, Smb2ReadRequest.LengthOffset, (uint)n);
        Wire.WriteUInt64LittleEndian(b, Smb2ReadRequest.OffsetFieldOffset, (ulong)offset);
        id.CopyTo(b, Smb2ReadRequest.FileIdOffset);
        try
        {
            var r = await ExchangeAsync(Smb2Command.Read, b, ct).ConfigureAwait(false);
            int length = checked((int)Wire.ReadUInt32LittleEndian(r, Smb2Header.Size + Smb2ReadResponse.DataLengthOffset));
            if (length > n)
                throw new SmbException(NtStatus.InvalidParameter);
            Wire.Slice(r, r[Smb2Header.Size + Smb2ReadResponse.DataOffsetFieldOffset], length).CopyTo(buffer.Span);
            return length;
        }
        catch (SmbException e) when (e.NtStatus == NtStatus.EndOfFile)
        {
            return 0;
        }
    }

    internal async Task WriteAsync(byte[] id, ReadOnlyMemory<byte> data, long offset, CancellationToken ct)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        while (data.Length > 0)
        {
            int n = Math.Min(data.Length, SmbLimits.MaxTransferSize);
            var b = new byte[Smb2WriteRequest.FixedSize + n];
            Wire.WriteUInt16LittleEndian(b, 0, Smb2WriteRequest.StructureSize);
            Wire.WriteUInt16LittleEndian(b, Smb2WriteRequest.DataOffsetFieldOffset, Smb2Header.Size + Smb2WriteRequest.FixedSize);
            Wire.WriteUInt32LittleEndian(b, Smb2WriteRequest.LengthOffset, (uint)n);
            Wire.WriteUInt64LittleEndian(b, Smb2WriteRequest.OffsetFieldOffset, checked((ulong)offset));
            id.CopyTo(b, Smb2WriteRequest.FileIdOffset);
            data.Span[..n].CopyTo(b.AsSpan(Smb2WriteRequest.FixedSize));
            var r = await ExchangeAsync(Smb2Command.Write, b, ct).ConfigureAwait(false);
            int written = checked((int)Wire.ReadUInt32LittleEndian(r, Smb2Header.Size + Smb2WriteResponse.CountOffset));
            if (written < 1 || written > n)
                throw new IOException("Invalid SMB write count.");
            offset = checked(offset + written);
            data = data[written..];
        }
    }

    internal async Task CloseAsync(byte[] id, CancellationToken ct)
    {
        var b = new byte[Smb2CloseRequest.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb2CloseRequest.StructureSize);
        id.CopyTo(b, Smb2CloseRequest.FileIdOffset);
        _ = await ExchangeAsync(Smb2Command.Close, b, ct).ConfigureAwait(false);
    }

    internal async Task FlushAsync(byte[] id, CancellationToken ct)
    {
        var b = new byte[Smb2FlushRequest.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb2FlushRequest.StructureSize);
        id.CopyTo(b, Smb2FlushRequest.FileIdOffset);
        _ = await ExchangeAsync(Smb2Command.Flush, b, ct).ConfigureAwait(false);
    }

    internal async Task SetAsync(byte[] id, int cls, byte[] data, CancellationToken ct)
    {
        var b = new byte[Smb2SetInfoRequest.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb2SetInfoRequest.StructureSize);
        b[Smb2SetInfoRequest.InfoTypeOffset] = Smb2InfoType.File;
        b[Smb2SetInfoRequest.FileInfoClassOffset] = (byte)cls;
        Wire.WriteUInt32LittleEndian(b, Smb2SetInfoRequest.BufferLengthOffset, (uint)data.Length);
        Wire.WriteUInt16LittleEndian(b, Smb2SetInfoRequest.BufferOffsetFieldOffset, Smb2Header.Size + Smb2SetInfoRequest.FixedSize);
        id.CopyTo(b, Smb2SetInfoRequest.FileIdOffset);
        _ = await ExchangeAsync(Smb2Command.SetInfo, Wire.Join(b, data), ct).ConfigureAwait(false);
    }

    /// <summary>Queries file or directory metadata using a temporary remote handle.</summary>
    public async Task<SmbEntry> GetInfoAsync(string path, bool directory = false, CancellationToken ct = default)
    {
        await using var file = await OpenCoreAsync(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, directory, ct).ConfigureAwait(false);
        var b = new byte[Smb2QueryInfoRequest.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb2QueryInfoRequest.StructureSize);
        b[Smb2QueryInfoRequest.InfoTypeOffset] = Smb2InfoType.File;
        b[Smb2QueryInfoRequest.FileInfoClassOffset] = FileInformationClass.NetworkOpenInformation;
        Wire.WriteUInt32LittleEndian(b, Smb2QueryInfoRequest.OutputBufferLengthOffset, FileNetworkOpenInformation.Size);
        file.Id.CopyTo(b, Smb2QueryInfoRequest.FileIdOffset);
        var r = await ExchangeAsync(Smb2Command.QueryInfo, b, ct).ConfigureAwait(false);
        var data = Wire.Slice(r, Wire.ReadUInt16LittleEndian(r, Smb2Header.Size + Smb2QueryResponse.OutputBufferOffsetFieldOffset), checked((int)Wire.ReadUInt32LittleEndian(r, Smb2Header.Size + Smb2QueryResponse.OutputBufferLengthOffset)));
        return new(path, checked((long)Wire.ReadUInt64LittleEndian(data, FileNetworkOpenInformation.EndOfFileOffset)), (FileAttributes)Wire.ReadUInt32LittleEndian(data, FileNetworkOpenInformation.FileAttributesOffset), DateTime.FromFileTimeUtc(checked((long)Wire.ReadUInt64LittleEndian(data, FileBasicInformation.CreationTimeOffset))), DateTime.FromFileTimeUtc(checked((long)Wire.ReadUInt64LittleEndian(data, FileBasicInformation.LastWriteTimeOffset))))
        {
            LastAccessTimeUtc = DateTime.FromFileTimeUtc(checked((long)Wire.ReadUInt64LittleEndian(data, FileBasicInformation.LastAccessTimeOffset))),
            ChangeTimeUtc = DateTime.FromFileTimeUtc(checked((long)Wire.ReadUInt64LittleEndian(data, FileBasicInformation.ChangeTimeOffset)))
        };
    }

    /// <summary>Reads until EOF into an owned array; use OpenAsync for larger streamed transfers.</summary>
    public async Task<byte[]> ReadAllBytesAsync(string path, CancellationToken ct = default)
    {
        await using var file = await OpenAsync(path, ct: ct).ConfigureAwait(false);
        if (file.Length > int.MaxValue)
            throw new IOException("File exceeds byte-array capacity; use OpenAsync.");
        using var result = new MemoryStream((int)file.Length);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(SmbLimits.MaxTransferSize);
        try
        {
            int count;
            // Continue to EOF even if the file has grown since CREATE returned its size.
            while ((count = await file.ReadAsync(buffer.AsMemory(0, SmbLimits.MaxTransferSize), result.Length, ct).ConfigureAwait(false)) > 0)
            {
                if (result.Length + count > int.MaxValue)
                    throw new IOException("File exceeds byte-array capacity.");
                result.Write(buffer.AsSpan(0, count));
            }

            // Transfer the exclusively owned backing array when no resizing is needed.
            byte[] contents = result.GetBuffer();
            return contents.Length == result.Length ? contents : result.ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <summary>Creates or replaces a file and requests durable storage before closing it.</summary>
    public async Task WriteAllBytesAsync(string path, ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        await using var f = await OpenAsync(path, FileMode.Create, FileAccess.ReadWrite, ct: ct).ConfigureAwait(false);
        await f.WriteAsync(data, 0, ct).ConfigureAwait(false);
        await f.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Creates a share-relative directory, or opens it if it already exists.</summary>
    public async Task CreateDirectoryAsync(string path, CancellationToken ct = default)
    {
        await using var f = await OpenCoreAsync(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, true, ct).ConfigureAwait(false);
    }

    /// <summary>Marks an object for deletion when its last sharing handle closes.</summary>
    public async Task DeleteAsync(string path, bool directory = false, CancellationToken ct = default)
    {
        await using var f = await OpenCoreAsync(path, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, directory, ct).ConfigureAwait(false);
        await SetAsync(f.Id, FileInformationClass.DispositionInformation, [1], ct).ConfigureAwait(false);
    }

    /// <summary>Renames a share-relative file, optionally replacing an existing destination.</summary>
    public async Task MoveAsync(string source, string destination, bool replace = false, CancellationToken ct = default)
    {
        await using var f = await OpenAsync(source, FileMode.Open, FileAccess.ReadWrite, ct: ct).ConfigureAwait(false);
        var name = Encoding.Unicode.GetBytes(destination.Replace('/', '\\'));
        var b = new byte[FileRenameInformation.FixedSize];
        b[FileRenameInformation.ReplaceIfExistsOffset] = replace ? (byte)1 : (byte)0;
        Wire.WriteUInt32LittleEndian(b, FileRenameInformation.FileNameLengthOffset, (uint)name.Length);
        await SetAsync(f.Id, FileInformationClass.RenameInformation, Wire.Join(b, name), ct).ConfigureAwait(false);
    }

    /// <summary>Collects every directory page, excluding the dot and dot-dot entries.</summary>
    public async Task<IReadOnlyList<SmbEntry>> ListDirectoryAsync(string path = "", CancellationToken ct = default)
    {
        await using var f = await OpenCoreAsync(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, true, ct).ConfigureAwait(false);
        var results = new List<SmbEntry>();
        bool first = true;
        while (true)
        {
            var b = new byte[Smb2QueryDirectoryRequest.FixedSize + sizeof(char)];
            Wire.WriteUInt16LittleEndian(b, 0, Smb2QueryDirectoryRequest.StructureSize);
            b[Smb2QueryDirectoryRequest.FileInformationClassOffset] = FileInformationClass.IdBothDirectoryInformation;
            b[Smb2QueryDirectoryRequest.FlagsOffset] = first ? Smb2QueryDirectoryFlags.RestartScans : (byte)0;
            f.Id.CopyTo(b, Smb2QueryDirectoryRequest.FileIdOffset);
            Wire.WriteUInt16LittleEndian(b, Smb2QueryDirectoryRequest.FileNameOffsetFieldOffset, Smb2Header.Size + Smb2QueryDirectoryRequest.FixedSize);
            Wire.WriteUInt16LittleEndian(b, Smb2QueryDirectoryRequest.FileNameLengthOffset, sizeof(char));
            Wire.WriteUInt32LittleEndian(b, Smb2QueryDirectoryRequest.OutputBufferLengthOffset, SmbLimits.MaxTransferSize);
            b[Smb2QueryDirectoryRequest.FixedSize] = (byte)'*';
            first = false;
            byte[] r;
            try
            {
                r = await ExchangeAsync(Smb2Command.QueryDirectory, b, ct).ConfigureAwait(false);
            }
            catch (SmbException e) when (e.NtStatus == NtStatus.NoMoreFiles)
            {
                break;
            }

            int o = Wire.ReadUInt16LittleEndian(r, Smb2Header.Size + Smb2QueryResponse.OutputBufferOffsetFieldOffset), n = checked((int)Wire.ReadUInt32LittleEndian(r, Smb2Header.Size + Smb2QueryResponse.OutputBufferLengthOffset));
            var data = Wire.Slice(r, o, n);
            int p = 0;
            while (true)
            {
                var entry = Wire.Slice(data, p, data.Length - p);
                if (entry.Length < FileDirectoryInformation.IdBothFixedSize)
                    throw new SmbException(NtStatus.InvalidParameter);
                string name = Wire.Text(Wire.Slice(entry, FileDirectoryInformation.IdBothFixedSize, checked((int)Wire.ReadUInt32LittleEndian(entry, FileDirectoryInformation.FileNameLengthOffset))));
                if (name is not ("." or ".."))
                    results.Add(new(name, checked((long)Wire.ReadUInt64LittleEndian(entry, FileDirectoryInformation.EndOfFileOffset)), (FileAttributes)Wire.ReadUInt32LittleEndian(entry, FileDirectoryInformation.FileAttributesOffset), DateTime.FromFileTimeUtc(checked((long)Wire.ReadUInt64LittleEndian(entry, FileDirectoryInformation.NamesFileNameLengthOffset))), DateTime.FromFileTimeUtc(checked((long)Wire.ReadUInt64LittleEndian(entry, FileDirectoryInformation.LastWriteTimeOffset)))));
                int next = checked((int)Wire.ReadUInt32LittleEndian(entry, FileDirectoryInformation.NextEntryOffsetFieldOffset));
                if (next == 0)
                    break;
                if (next < FileDirectoryInformation.IdBothFixedSize || next > entry.Length || (next & 7) != 0)
                    throw new SmbException(NtStatus.InvalidParameter);
                p += next;
            }
        }

        return results;
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
            return;
        try
        {
            if (crypto != null && !failed && tcp.Connected)
            {
                try
                {
                    _ = await ExchangeAsync(Smb2Command.Logoff, Wire.CreateSimpleMessage(), CancellationToken.None).ConfigureAwait(false);
                }
                catch (IOException)
                {
                }
                catch (OperationCanceledException)
                {
                }
            }
        }
        finally
        {
            disposed = true;
            crypto?.Dispose();
            tcp.Dispose();
            gate.Dispose();
        }
    }
}

/// <summary>A remote handle with explicit-offset I/O; dispose it before its owning client.</summary>
/// <remarks>Length reflects operations through this handle, not concurrent remote writes.</remarks>
public sealed class SmbFile : IAsyncDisposable
{
    private readonly SmbClient client;
    internal byte[] Id { get; }

    private bool disposed;
    public long Length { get; private set; }

    internal SmbFile(SmbClient client, byte[] id, long length)
    {
        this.client = client;
        Id = id;
        Length = length;
    }

    /// <summary>Reads up to one negotiated transfer into caller-owned memory; zero means EOF.</summary>
    public Task<int> ReadAsync(Memory<byte> buffer, long offset, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return client.ReadAsync(Id, buffer, offset, ct);
    }

    /// <summary>Writes all supplied memory in bounded transfers at the specified offset.</summary>
    public async Task WriteAsync(ReadOnlyMemory<byte> data, long offset, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        await client.WriteAsync(Id, data, offset, ct).ConfigureAwait(false);
        Length = Math.Max(Length, checked(offset + data.Length));
    }

    /// <summary>Requests that the server flush this handle to durable storage.</summary>
    public Task FlushAsync(CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return client.FlushAsync(Id, ct);
    }

    /// <summary>Truncates or extends the remote file without changing an implicit position.</summary>
    public async Task SetLengthAsync(long length, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        var b = new byte[sizeof(ulong)];
        Wire.WriteUInt64LittleEndian(b, 0, (ulong)length);
        await client.SetAsync(Id, FileInformationClass.EndOfFileInformation, b, ct).ConfigureAwait(false);
        Length = length;
    }

    /// <summary>Sets selected UTC timestamps and attributes; null leaves a field unchanged.</summary>
    public Task SetMetadataAsync(DateTime? creationUtc = null, DateTime? accessUtc = null, DateTime? writeUtc = null, DateTime? changeUtc = null, FileAttributes? attributes = null, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var b = new byte[FileBasicInformation.Size];
        WriteTime(b, FileBasicInformation.CreationTimeOffset, creationUtc);
        WriteTime(b, FileBasicInformation.LastAccessTimeOffset, accessUtc);
        WriteTime(b, FileBasicInformation.LastWriteTimeOffset, writeUtc);
        WriteTime(b, FileBasicInformation.ChangeTimeOffset, changeUtc);
        if (attributes is { } value)
            Wire.WriteUInt32LittleEndian(b, FileBasicInformation.FileAttributesOffset, (uint)value);
        return client.SetAsync(Id, FileInformationClass.BasicInformation, b, ct);
    }

    private static void WriteTime(Span<byte> buffer, int offset, DateTime? value)
    {
        if (value is { } time)
            Wire.WriteUInt64LittleEndian(buffer, offset, checked((ulong)time.ToFileTimeUtc()));
    }

    public async ValueTask DisposeAsync()
    {
        if (disposed)
            return;
        disposed = true;
        await client.CloseAsync(Id, CancellationToken.None).ConfigureAwait(false);
    }
}
