using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Tedd.Smb;

/// <summary>One export root, local account, and bounded connection policy.</summary>
public sealed record SmbServerOptions
{
    public required string RootPath { get; init; }
    public string ShareName { get; init; } = "files";
    public required string UserName { get; init; }
    public required string Password { get; init; }
    public IPAddress ListenAddress { get; init; } = IPAddress.Loopback;
    public int Port { get; init; } = SmbLimits.DefaultPort;
    public bool Writable { get; init; }
    public bool RequireEncryption { get; init; } = true;
    public int MaxConnections { get; init; } = SmbLimits.DefaultMaxConnections;
    public Action<string>? Log { get; init; }
}

/// <summary>A bounded SMB 3.1.1 file server with a single configured local account and disk share.</summary>
public sealed class SmbServer : IAsyncDisposable
{
    internal readonly SmbServerOptions Options;
    // One async gate preserves share-access, rename and delete-on-close atomicity.
    internal readonly SemaphoreSlim FileGate = new(1, 1);
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
        if (!Directory.Exists(options.RootPath))
            throw new DirectoryNotFoundException(options.RootPath);
        if (string.IsNullOrWhiteSpace(options.UserName) || string.IsNullOrEmpty(options.Password) || string.IsNullOrWhiteSpace(options.ShareName) || options.ShareName.IndexOfAny(['\\', '/', ':']) >= 0 || options.ShareName.Equals("IPC$", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Invalid account or share configuration.");
        if (options.MaxConnections is < 1 or > SmbLimits.MaxConnections)
            throw new ArgumentOutOfRangeException(nameof(options));
        Options = options with
        {
            RootPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(options.RootPath))
        };
        if ((File.GetAttributes(Options.RootPath) & FileAttributes.ReparsePoint) != 0)
            throw new ArgumentException("Export root cannot be a link.");
        listener = new TcpListener(options.ListenAddress, options.Port);
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        // Track every accepted worker so shutdown waits for handle and key cleanup.
        if (started)
            throw new InvalidOperationException("Server already started.");
        started = true;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(stop.Token, cancellationToken);
        listener.Start();
        Options.Log?.Invoke($"Listening on {LocalEndPoint}; share {Options.ShareName}; SMB 3.1.1; encryption required={Options.RequireEncryption}.");
        try
        {
            while (!linked.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(linked.Token).ConfigureAwait(false);
                if (workers.Count >= Options.MaxConnections)
                {
                    client.Dispose();
                    continue;
                }

                long id = Interlocked.Increment(ref workerId);
                var task = ServeAsync(client, linked.Token);
                workers[id] = task;
                _ = task.ContinueWith(_ =>
                {
                    workers.TryRemove(id, out var ignored);
                }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (OperationCanceledException) when (linked.IsCancellationRequested)
        {
        }
        finally
        {
            linked.Cancel();
            listener.Stop();
            await Task.WhenAll(workers.Values).ConfigureAwait(false);
        }
    }

    private async Task ServeAsync(TcpClient client, CancellationToken ct)
    {
        using (client)
        await using (var connection = new ServerConnection(this))
        {
            try
            {
                client.NoDelay = true;
                var transport = new SmbTransport(client.GetStream());
                while (!ct.IsCancellationRequested)
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(connection.Authenticated ? TimeSpan.FromMinutes(15) : TimeSpan.FromSeconds(30));
                    var request = await transport.ReceiveAsync(timeout.Token).ConfigureAwait(false);
                    var response = await connection.ProcessAsync(request, timeout.Token).ConfigureAwait(false);
                    if (response.Length != 0)
                        await transport.SendAsync(response, timeout.Token).ConfigureAwait(false);
                    if (connection.LoggedOff)
                        break;
                }
            }
            catch (Exception e) when (e is IOException or SocketException or OperationCanceledException or CryptographicException or ArgumentException or OverflowException)
            {
                Options.Log?.Invoke($"Connection closed: {e.GetType().Name}: {e.Message}");
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync().ConfigureAwait(false);
        listener.Stop();
        await Task.WhenAll(workers.Values).ConfigureAwait(false);
        stop.Dispose();
    }
}

/// <summary>Per-channel authentication, credits, compound dispatch, and tree state.</summary>
/// <remarks>A single receive loop awaits each command before accepting another frame.</remarks>
internal sealed class ServerConnection : IAsyncDisposable
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
    private byte[] preauth = new byte[Smb3Cryptography.PreauthHashSize];
    private bool negotiated;
    private bool challenged;
    private bool rawNtlm;
    private int cipher;
    internal bool Authenticated => crypto != null;
    internal bool LoggedOff { get; private set; }

    internal ServerConnection(SmbServer server)
    {
        this.server = server;
        auth = new(server.Options.UserName, server.Options.Password);
        files = new(server);
    }

    internal async ValueTask<byte[]> ProcessAsync(byte[] packet, CancellationToken cancellationToken = default)
    {
        if (packet.Length < Smb3TransformHeader.Size)
            throw new SmbException(NtStatus.InvalidParameter);
        if (packet[Smb3Header.ProtocolIdOffset] == Smb1NegotiateEnvelope.ProtocolPrefix)
            return LegacyNegotiate(packet);
        bool encrypted = packet[Smb3Header.ProtocolIdOffset] == Smb3TransformHeader.ProtocolPrefix;
        if (encrypted)
            packet = (crypto ?? throw new SmbException(NtStatus.AccessDenied)).Decrypt(packet, session);
        Wire.Validate(packet);
        if (Wire.ReadUInt16LittleEndian(packet, Smb3Header.CommandOffset) == Smb3Command.Cancel)
        {
            // Requests on this channel finish before the next is received. CANCEL has no
            // response and refers to an earlier MessageId, consuming no credit.
            if (!Authenticated || Wire.ReadUInt64LittleEndian(packet, Smb3Header.SessionIdOffset) != session || packet.Length != Smb3Header.Size + Smb3SimpleMessage.FixedSize || Wire.ReadUInt32LittleEndian(packet, Smb3Header.NextCommandOffset) != 0 || Wire.ReadUInt16LittleEndian(packet, Smb3Header.Size) != Smb3SimpleMessage.StructureSize || (server.Options.RequireEncryption && !encrypted))
                throw new SmbException(NtStatus.InvalidParameter);
            if (!encrypted)
                crypto!.Verify(packet);
            return [];
        }

        // Views retain the owning frame across awaits; every signature is checked
        // before any related-operation substitutions or filesystem effects.
        var requests = new List<ReadOnlyMemory<byte>>();
        int p = 0;
        while (true)
        {
            if (requests.Count >= SmbLimits.MaxCompoundCommands)
                throw new SmbException(NtStatus.InvalidParameter);
            var rest = packet.AsSpan(p);
            Wire.Validate(rest);
            uint next = Wire.ReadUInt32LittleEndian(rest, Smb3Header.NextCommandOffset);
            if (next != 0 && (next < Smb3Header.Size || next > rest.Length - Smb3Header.Size || (next & 7) != 0))
                throw new SmbException(NtStatus.InvalidParameter);
            var request = packet.AsMemory(p, next == 0 ? rest.Length : checked((int)next));
            if (Wire.ReadUInt16LittleEndian(request.Span, Smb3Header.CreditChargeOffset) > 1 || !credits.Remove(Wire.ReadUInt64LittleEndian(request.Span, Smb3Header.MessageIdOffset)) || (Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.FlagsOffset) & Smb3HeaderFlags.ResponseOrAsync) != 0)
                throw new SmbException(NtStatus.InvalidParameter);
            if (Authenticated && !encrypted)
                crypto!.Verify(request.Span);
            requests.Add(request);
            if (next == 0)
                break;
            p += (int)next;
        }

        if (requests.Count != 1 && requests.Any(x => Wire.ReadUInt16LittleEndian(x.Span, Smb3Header.CommandOffset) <= Smb3Command.SessionSetup))
            throw new SmbException(NtStatus.InvalidParameter);
        var replies = new List<byte[]>(requests.Count);
        uint lastTree = 0;
        bool relatedFailed = false;
        foreach (var original in requests)
        {
            var request = original;
            ushort cmd = Wire.ReadUInt16LittleEndian(request.Span, Smb3Header.CommandOffset);
            bool related = (Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.FlagsOffset) & Smb3HeaderFlags.RelatedOperations) != 0;
            if (related)
            {
                if (replies.Count == 0)
                    throw new SmbException(NtStatus.InvalidParameter);
                // Only related commands need a private mutable header.
                byte[] substituted = original.ToArray();
                Wire.WriteUInt64LittleEndian(substituted, Smb3Header.SessionIdOffset, session);
                Wire.WriteUInt32LittleEndian(substituted, Smb3Header.TreeIdOffset, lastTree);
                request = substituted;
            }
            else
            {
                relatedFailed = false;
                files.RelatedId = null;
            }

            uint status = NtStatus.Success;
            byte[] body;
            uint tree = Wire.ReadUInt32LittleEndian(request.Span, Smb3Header.TreeIdOffset);
            if (cmd is Smb3Command.Negotiate or Smb3Command.SessionSetup)
                preauth = Negotiation.Hash(preauth, original.Span);
            try
            {
                if (relatedFailed)
                    throw new SmbException(NtStatus.InvalidParameter);
                if (cmd == Smb3Command.Negotiate)
                    body = Negotiate(request.Span);
                else if (cmd == Smb3Command.SessionSetup)
                    body = Setup(request.Span, out status);
                else
                {
                    if (!Authenticated || Wire.ReadUInt64LittleEndian(request.Span, Smb3Header.SessionIdOffset) != session)
                        throw new SmbException(NtStatus.UserSessionDeleted);
                    if (server.Options.RequireEncryption && !encrypted)
                        throw new SmbException(NtStatus.AccessDenied);
                    if (cmd == Smb3Command.TreeConnect)
                    {
                        body = TreeConnect(request.Span, out tree);
                    }
                    else if (cmd is Smb3Command.Logoff or Smb3Command.Echo)
                    {
                        body = Wire.CreateSimpleMessage();
                        if (cmd == Smb3Command.Logoff)
                            LoggedOff = true;
                    }
                    else
                    {
                        if (!trees.TryGetValue(tree, out bool pipe))
                            throw new SmbException(NtStatus.NetworkNameDeleted);
                        if (cmd == Smb3Command.TreeDisconnect)
                        {
                            await files.CloseTreeAsync(tree, cancellationToken).ConfigureAwait(false);
                            trees.Remove(tree);
                            body = Wire.CreateSimpleMessage();
                        }
                        else
                            body = await files.DispatchAsync(cmd, request, tree, pipe, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or OverflowException or NotSupportedException)
            {
                status = MapError(e);
                body = new byte[Smb3ErrorResponse.MinimumSize];
                Wire.WriteUInt16LittleEndian(body, 0, Smb3ErrorResponse.StructureSize);
                relatedFailed = true;
                server.Options.Log?.Invoke($"Command {cmd}: 0x{status:X8} ({e.Message})");
            }

            var response = Wire.Packet(cmd, Wire.ReadUInt64LittleEndian(request.Span, Smb3Header.MessageIdOffset), cmd == Smb3Command.Negotiate ? 0 : session, tree, body);
            Wire.WriteUInt32LittleEndian(response, Smb3Header.StatusOffset, status);
            Wire.WriteUInt32LittleEndian(response, Smb3Header.FlagsOffset, Smb3HeaderFlags.ServerToRedir | (related ? Smb3HeaderFlags.RelatedOperations : 0u));
            int grant = Math.Min(Math.Max(1, (int)Wire.ReadUInt16LittleEndian(request.Span, Smb3Header.CreditsOffset)), SmbLimits.MaxCredits - credits.Count);
            for (int i = 0; i < grant; i++)
                credits.Add(nextCredit++);
            Wire.WriteUInt16LittleEndian(response, Smb3Header.CreditsOffset, grant);
            lastTree = tree;
            if (cmd == Smb3Command.Negotiate || (cmd == Smb3Command.SessionSetup && status == NtStatus.MoreProcessingRequired))
                preauth = Negotiation.Hash(preauth, response);
            replies.Add(response);
        }

        for (int i = 0; i < replies.Count; i++)
        {
            // Padding and NextCommand are covered by each individual SMB signature.
            var r = replies[i];
            if (i < replies.Count - 1)
            {
                Array.Resize(ref r, Wire.Align(r.Length));
                Wire.WriteUInt32LittleEndian(r, Smb3Header.NextCommandOffset, (uint)r.Length);
                replies[i] = r;
            }

            if (Authenticated && !encrypted)
                crypto!.Sign(r);
        }

        var result = replies.Count == 1 ? replies[0] : Wire.Join(replies.ToArray());
        return encrypted ? crypto!.Encrypt(result, session) : result;
    }

    private byte[] LegacyNegotiate(byte[] request)
    {
        // SMB1 is accepted only as the compatibility envelope for SMB2 negotiation.
        if (negotiated || challenged || request.Length < Smb1NegotiateEnvelope.FixedSize || request[Smb1NegotiateEnvelope.CommandOffset] != Smb1NegotiateEnvelope.NegotiateCommand || Wire.ReadUInt32LittleEndian(request, 0) != Smb1NegotiateEnvelope.ProtocolId || request[Smb1NegotiateEnvelope.WordCountOffset] != 0 || Wire.ReadUInt16LittleEndian(request, Smb1NegotiateEnvelope.ByteCountOffset) != request.Length - Smb1NegotiateEnvelope.FixedSize || request.AsSpan(Smb1NegotiateEnvelope.FixedSize).IndexOf("SMB 2.???\0"u8) < 0)
            throw new SmbException(NtStatus.NotSupported);
        var b = Wire.Join(Wire.Header(Smb3Command.Negotiate, 0), new byte[Smb3NegotiateResponse.FixedSize], Spnego.Initial);
        Wire.WriteUInt32LittleEndian(b, Smb3Header.FlagsOffset, Smb3HeaderFlags.ServerToRedir);
        Wire.WriteUInt16LittleEndian(b, Smb3Header.CreditsOffset, 1);
        Wire.WriteUInt16LittleEndian(b, Smb3Header.Size, Smb3NegotiateResponse.StructureSize);
        Wire.WriteUInt16LittleEndian(b, Smb3Header.Size + Smb3NegotiateResponse.SecurityModeOffset, Smb3SecurityMode.SigningEnabledAndRequired);
        Wire.WriteUInt16LittleEndian(b, Smb3Header.Size + Smb3NegotiateResponse.DialectRevisionOffset, Smb3Dialect.Wildcard);
        server.GuidBytes.CopyTo(b, Smb3Header.Size + Smb3NegotiateResponse.ServerGuidOffset);
        Wire.WriteUInt32LittleEndian(b, Smb3Header.Size + Smb3NegotiateResponse.MaxTransactSizeOffset, SmbLimits.MaxTransferSize);
        Wire.WriteUInt32LittleEndian(b, Smb3Header.Size + Smb3NegotiateResponse.MaxReadSizeOffset, SmbLimits.MaxTransferSize);
        Wire.WriteUInt32LittleEndian(b, Smb3Header.Size + Smb3NegotiateResponse.MaxWriteSizeOffset, SmbLimits.MaxTransferSize);
        Wire.WriteUInt64LittleEndian(b, Smb3Header.Size + Smb3NegotiateResponse.SystemTimeOffset, (ulong)DateTime.UtcNow.ToFileTimeUtc());
        Wire.WriteUInt16LittleEndian(b, Smb3Header.Size + Smb3NegotiateResponse.SecurityBufferOffsetFieldOffset, Smb3Header.Size + Smb3NegotiateResponse.FixedSize);
        Wire.WriteUInt16LittleEndian(b, Smb3Header.Size + Smb3NegotiateResponse.SecurityBufferLengthOffset, Spnego.Initial.Length);
        credits.Clear();
        credits.Add(1);
        nextCredit = 2;
        return b;
    }

    private byte[] Negotiate(ReadOnlySpan<byte> request)
    {
        if (negotiated || request.Length < Smb3Header.Size + Smb3NegotiateRequest.FixedSize + sizeof(ushort) || Wire.ReadUInt16LittleEndian(request, Smb3Header.Size) != Smb3NegotiateRequest.StructureSize)
            throw new SmbException(NtStatus.InvalidParameter);
        int count = Wire.ReadUInt16LittleEndian(request, Smb3Header.Size + Smb3NegotiateRequest.DialectCountOffset);
        var dialects = Wire.Slice(request, Smb3Header.Size + Smb3NegotiateRequest.DialectsOffset, checked(count * sizeof(ushort)));
        bool found = false;
        for (int i = 0; i < count; i++)
            if (Wire.ReadUInt16LittleEndian(dialects, i * sizeof(ushort)) == Smb3Dialect.Smb311)
                found = true;
        if (!found)
            throw new SmbException(NtStatus.NotSupported);
        int offset = checked((int)Wire.ReadUInt32LittleEndian(request, Smb3Header.Size + Smb3NegotiateRequest.NegotiateContextOffsetFieldOffset));
        if (offset < Wire.Align(Smb3Header.Size + Smb3NegotiateRequest.DialectsOffset + count * sizeof(ushort)))
            throw new SmbException(NtStatus.InvalidParameter);
        var algorithms = Negotiation.ValidateContexts(request, offset, Wire.ReadUInt16LittleEndian(request, Smb3Header.Size + Smb3NegotiateRequest.NegotiateContextCountOffset), false);
        bool signing = algorithms.Signing;
        cipher = algorithms.Cipher;
        int ctxOffset = Wire.Align(Smb3Header.Size + Smb3NegotiateResponse.FixedSize + Spnego.Initial.Length);
        var b = new byte[ctxOffset - Smb3Header.Size];
        Wire.WriteUInt16LittleEndian(b, 0, Smb3NegotiateResponse.StructureSize);
        Wire.WriteUInt16LittleEndian(b, Smb3NegotiateResponse.SecurityModeOffset, Smb3SecurityMode.SigningEnabledAndRequired);
        Wire.WriteUInt16LittleEndian(b, Smb3NegotiateResponse.DialectRevisionOffset, Smb3Dialect.Smb311);
        Wire.WriteUInt16LittleEndian(b, Smb3NegotiateResponse.NegotiateContextCountOffset, signing ? Negotiation.ContextCountWithSigning : Negotiation.BaseContextCount);
        server.GuidBytes.CopyTo(b, Smb3NegotiateResponse.ServerGuidOffset);
        Wire.WriteUInt32LittleEndian(b, Smb3NegotiateResponse.CapabilitiesOffset, Smb3GlobalCapabilities.Encryption);
        Wire.WriteUInt32LittleEndian(b, Smb3NegotiateResponse.MaxTransactSizeOffset, SmbLimits.MaxTransferSize);
        Wire.WriteUInt32LittleEndian(b, Smb3NegotiateResponse.MaxReadSizeOffset, SmbLimits.MaxTransferSize);
        Wire.WriteUInt32LittleEndian(b, Smb3NegotiateResponse.MaxWriteSizeOffset, SmbLimits.MaxTransferSize);
        Wire.WriteUInt64LittleEndian(b, Smb3NegotiateResponse.SystemTimeOffset, (ulong)DateTime.UtcNow.ToFileTimeUtc());
        Wire.WriteUInt16LittleEndian(b, Smb3NegotiateResponse.SecurityBufferOffsetFieldOffset, Smb3Header.Size + Smb3NegotiateResponse.FixedSize);
        Wire.WriteUInt16LittleEndian(b, Smb3NegotiateResponse.SecurityBufferLengthOffset, Spnego.Initial.Length);
        Wire.WriteUInt32LittleEndian(b, Smb3NegotiateResponse.NegotiateContextOffsetFieldOffset, (uint)ctxOffset);
        Spnego.Initial.CopyTo(b, Smb3NegotiateResponse.FixedSize);
        negotiated = true;
        return Wire.Join(b, Negotiation.Contexts(signing, cipher));
    }

    private byte[] Setup(ReadOnlySpan<byte> request, out uint status)
    {
        if (!negotiated || Authenticated || request.Length < Smb3Header.Size + Smb3SessionSetupRequest.FixedSize || Wire.ReadUInt16LittleEndian(request, Smb3Header.Size) != Smb3SessionSetupRequest.StructureSize || request[Smb3Header.Size + Smb3SessionSetupRequest.FlagsOffset] != 0 || Wire.ReadUInt64LittleEndian(request, Smb3Header.Size + Smb3SessionSetupRequest.PreviousSessionIdOffset) != 0 || Wire.ReadUInt64LittleEndian(request, Smb3Header.SessionIdOffset) != (challenged ? session : 0))
            throw new SmbException(NtStatus.InvalidParameter);
        int o = Wire.ReadUInt16LittleEndian(request, Smb3Header.Size + Smb3SessionSetupRequest.SecurityBufferOffsetFieldOffset), n = Wire.ReadUInt16LittleEndian(request, Smb3Header.Size + Smb3SessionSetupRequest.SecurityBufferLengthOffset);
        if (o < Smb3Header.Size + Smb3SessionSetupRequest.FixedSize || n > SmbLimits.MaxAuthenticationTokenSize)
            throw new SmbException(NtStatus.InvalidParameter);
        var input = Wire.Slice(request, o, n).ToArray();
        if (!challenged)
            rawNtlm = input.AsSpan().StartsWith("NTLMSSP\0"u8);
        var token = Spnego.Unwrap(input);
        byte[] output;
        if (!challenged)
        {
            var challenge = auth.Challenge(token);
            output = rawNtlm ? challenge : Spnego.Response(challenge, true);
            challenged = true;
            status = NtStatus.MoreProcessingRequired;
        }
        else
        {
            var key = auth.Authenticate(token);
            try
            {
                crypto = new SessionCrypto(key, preauth, true, cipher);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }

            output = rawNtlm ? [] : Spnego.Response([], false);
            status = NtStatus.Success;
        }

        var b = new byte[Smb3SessionSetupResponse.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb3SessionSetupResponse.StructureSize);
        Wire.WriteUInt16LittleEndian(b, Smb3SessionSetupResponse.SessionFlagsOffset, Authenticated && server.Options.RequireEncryption ? Smb3SessionFlags.EncryptData : 0);
        Wire.WriteUInt16LittleEndian(b, Smb3SessionSetupResponse.SecurityBufferOffsetFieldOffset, Smb3Header.Size + Smb3SessionSetupResponse.FixedSize);
        Wire.WriteUInt16LittleEndian(b, Smb3SessionSetupResponse.SecurityBufferLengthOffset, output.Length);
        return Wire.Join(b, output);
    }

    private byte[] TreeConnect(ReadOnlySpan<byte> request, out uint id)
    {
        if (request.Length < Smb3Header.Size + Smb3TreeConnectRequest.FixedSize || Wire.ReadUInt16LittleEndian(request, Smb3Header.Size) != Smb3TreeConnectRequest.StructureSize)
            throw new SmbException(NtStatus.InvalidParameter);
        var path = Wire.Text(Wire.Slice(request, Wire.ReadUInt16LittleEndian(request, Smb3Header.Size + Smb3TreeConnectRequest.PathOffsetFieldOffset), Wire.ReadUInt16LittleEndian(request, Smb3Header.Size + Smb3TreeConnectRequest.PathLengthOffset))).Split('\\');
        if (path.Length != 4 || path[0] != "" || path[1] != "" || path[2].Length == 0)
            throw new SmbException(NtStatus.BadNetworkName);
        bool pipe = path[3].Equals("IPC$", StringComparison.OrdinalIgnoreCase);
        if (!pipe && !path[3].Equals(server.Options.ShareName, StringComparison.OrdinalIgnoreCase))
            throw new SmbException(NtStatus.BadNetworkName);
        if (trees.Count >= SmbLimits.MaxTrees)
            throw new SmbException(NtStatus.BufferTooSmall);
        id = ++nextTree;
        trees.Add(id, pipe);
        var b = new byte[Smb3TreeConnectResponse.FixedSize];
        Wire.WriteUInt16LittleEndian(b, 0, Smb3TreeConnectResponse.StructureSize);
        b[Smb3TreeConnectResponse.ShareTypeOffset] = pipe ? Smb3ShareType.Pipe : Smb3ShareType.Disk;
        Wire.WriteUInt32LittleEndian(b, Smb3TreeConnectResponse.ShareFlagsOffset, Smb3ShareFlags.NoCaching | (server.Options.RequireEncryption ? Smb3ShareFlags.EncryptData : 0));
        Wire.WriteUInt32LittleEndian(b, Smb3TreeConnectResponse.MaximalAccessOffset, server.Options.Writable ? FileAccessMask.FileAllAccess : SmbLimits.ReadAccess);
        return b;
    }

    internal static uint MapError(Exception e) => e switch
    {
        SmbException smb => smb.NtStatus,
        FileNotFoundException or DirectoryNotFoundException => NtStatus.ObjectNameNotFound,
        UnauthorizedAccessException => NtStatus.AccessDenied,
        ArgumentException or OverflowException => NtStatus.InvalidParameter,
        NotSupportedException => NtStatus.NotSupported,
        IOException io when (io.HResult & 0xffff) == 32 => NtStatus.SharingViolation,
        _ => NtStatus.AccessDenied
    };
    public async ValueTask DisposeAsync()
    {
        try
        {
            await files.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            crypto?.Dispose();
        }
    }
}
