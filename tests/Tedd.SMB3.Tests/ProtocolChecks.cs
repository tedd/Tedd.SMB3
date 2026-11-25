using System.Security.Cryptography;
using System.Text;
using Tedd.SMB3;

/// <summary>Adversarial packet fixtures independent of the client serializer.</summary>
internal static class ProtocolChecks
{
    internal static async Task RunAsync(string root)
    {
        async Task Rejected(Func<ValueTask<byte[]>> action, string label)
        {
            try { await action(); } catch (Exception e) when (e is SmbException or CryptographicException or ArgumentException) { Console.WriteLine("PASS " + label); return; }
            throw new Exception("Accepted invalid request: " + label);
        }
        await using (var s = await Session.CreateAsync(root))
        {
            var p = s.Request(13, [4, 0, 0, 0]); s.Crypto.Sign(p); _ = await s.Connection.ProcessAsync(p);
            await Rejected(() => s.Connection.ProcessAsync(p), "signed message replay rejected");
        }
        await using (var s = await Session.CreateAsync(root))
        {
            var p = s.Crypto.Encrypt(s.Request(13, [4, 0, 0, 0]), s.SessionId); _ = await s.Connection.ProcessAsync(p);
            await Rejected(() => s.Connection.ProcessAsync(p), "encrypted message replay rejected");
        }
        await using (var s = await Session.CreateAsync(root))
        { var p = s.Request(13, [4, 0, 0, 0]); s.Crypto.Sign(p); p[^1] ^= 1; await Rejected(() => s.Connection.ProcessAsync(p), "altered signed command rejected"); }
        await using (var s = await Session.CreateAsync(root))
        { var p = s.Request(13, [4, 0, 0, 0]); await Rejected(() => s.Connection.ProcessAsync(p), "unsigned authenticated command rejected"); }
        await using (var s = await Session.CreateAsync(root))
        {
            var p = s.Request(13, new byte[4096]); s.Crypto.Sign(p);
            p = SmbCompression.Compress(p);
            if (p[0] != 0xfc) throw new Exception("Compression fixture did not compress.");
            await Rejected(() => s.Connection.ProcessAsync(p), "compression without negotiation rejected");
        }
        await using (var s = await Session.CreateAsync(root))
        { var p = s.Request(13, [4, 0, 0, 0]); Wire.WriteUInt32LittleEndian(p, 20, 65); await Rejected(() => s.Connection.ProcessAsync(p), "unaligned compound rejected"); }
        await using (var s = await Session.CreateAsync(root))
        {
            var cancel = s.Request(12, [4, 0, 0, 0]); Wire.WriteUInt64LittleEndian(cancel, 24, 1); s.Crypto.Sign(cancel);
            if ((await s.Connection.ProcessAsync(cancel)).Length != 0) throw new Exception("CANCEL generated a reply.");
            var echo = s.Request(13, [4, 0, 0, 0]); s.Crypto.Sign(echo); var reply = await s.Connection.ProcessAsync(echo); s.Crypto.Verify(reply);
            Console.WriteLine("PASS completed-request CANCEL has no reply and preserves connection");
        }
        await MultiCreditAsync(root);
        await using (var legacy = await Session.CreateAsync(root))
        {
            var read = legacy.Request(8, new byte[49], 2);
            legacy.Crypto.Sign(read);
            await Rejected(() => legacy.Connection.ProcessAsync(read), "multi-credit request without negotiation");
        }
        foreach (bool encrypt in new[] { false, true })
            await using (var s = await Session.CreateAsync(root))
            {
                var path = Encoding.Unicode.GetBytes("compound-" + Guid.NewGuid().ToString("N"));
                var create = new byte[56]; Wire.WriteUInt16LittleEndian(create, 0, 57); Wire.WriteUInt32LittleEndian(create, 24, 0x13019f); Wire.WriteUInt32LittleEndian(create, 32, 7); Wire.WriteUInt32LittleEndian(create, 36, 2); Wire.WriteUInt32LittleEndian(create, 40, 0x40); Wire.WriteUInt16LittleEndian(create, 44, 120); Wire.WriteUInt16LittleEndian(create, 46, path.Length);
                var payload = Encoding.UTF8.GetBytes("compound write payload"); var write = new byte[48]; Wire.WriteUInt16LittleEndian(write, 0, 49); Wire.WriteUInt16LittleEndian(write, 2, 112); Wire.WriteUInt32LittleEndian(write, 4, (uint)payload.Length); write.AsSpan(16, 16).Fill(255);
                var close = new byte[24]; Wire.WriteUInt16LittleEndian(close, 0, 24); close.AsSpan(8, 16).Fill(255);
                var packets = new[] { s.Request(5, Wire.Join(create, path)), s.Request(9, Wire.Join(write, payload)), s.Request(6, close) };
                for (int i = 0; i < packets.Length; i++)
                {
                    if (i > 0) { Wire.WriteUInt32LittleEndian(packets[i], 16, 4); Wire.WriteUInt32LittleEndian(packets[i], 36, uint.MaxValue); Wire.WriteUInt64LittleEndian(packets[i], 40, ulong.MaxValue); }
                    if (i < packets.Length - 1) { var p = packets[i]; Array.Resize(ref p, Wire.Align(p.Length)); Wire.WriteUInt32LittleEndian(p, 20, (uint)p.Length); packets[i] = p; }
                    if (!encrypt) s.Crypto.Sign(packets[i]);
                }
                var request = Wire.Join(packets); var response = await s.Connection.ProcessAsync(encrypt ? s.Crypto.Encrypt(request, s.SessionId) : request);
                if (encrypt) response = s.Crypto.Decrypt(response, s.SessionId);
                int offset = 0;
                for (int i = 0; i < packets.Length; i++)
                {
                    int next = checked((int)Wire.ReadUInt32LittleEndian(response, offset + 20)); var part = response.AsSpan(offset, next == 0 ? response.Length - offset : next).ToArray();
                    if (!encrypt) s.Crypto.Verify(part);
                    if (Wire.ReadUInt32LittleEndian(part, 8) != 0) throw new Exception("Compound failed."); offset += part.Length;
                }
                string file = Path.Combine(root, Encoding.Unicode.GetString(path));
                if (!File.ReadAllBytes(file).AsSpan().SequenceEqual(payload)) throw new Exception("Compound data mismatch."); File.Delete(file);
                Console.WriteLine($"PASS related CREATE/WRITE/CLOSE compound encrypted={encrypt}");
            }
    }
    private static async Task MultiCreditAsync(string root)
    {
        string name = "credits-" + Guid.NewGuid().ToString("N");
        string path = Path.Combine(root, name);
        try
        {
            await using var session = await Session.CreateAsync(root, multiCredit: true);
            async Task<byte[]> Exchange(ushort command, byte[] body, ushort charge, uint status = 0)
            {
                var request = session.Request(command, body, charge);
                session.Crypto.Sign(request);
                var response = await session.Connection.ProcessAsync(request);
                session.Crypto.Verify(response);
                Check.Equal(status, Wire.ReadUInt32LittleEndian(response, 8), "multi-credit response status");
                Check.Equal(charge, Wire.ReadUInt16LittleEndian(response, 6), "response credit charge");
                return response;
            }

            var filename = Encoding.Unicode.GetBytes(name);
            var create = new byte[56];
            Wire.WriteUInt16LittleEndian(create, 0, 57);
            Wire.WriteUInt32LittleEndian(create, 24, 0x13019f);
            Wire.WriteUInt32LittleEndian(create, 32, 7);
            Wire.WriteUInt32LittleEndian(create, 36, 2);
            Wire.WriteUInt32LittleEndian(create, 40, 0x40);
            Wire.WriteUInt16LittleEndian(create, 44, 120);
            Wire.WriteUInt16LittleEndian(create, 46, filename.Length);
            var opened = await Exchange(5, Wire.Join(create, filename), 1);
            var ioctl = new byte[56];
            Wire.WriteUInt16LittleEndian(ioctl, 0, 57);
            Wire.WriteUInt32LittleEndian(ioctl, 32, uint.MaxValue);
            Wire.WriteUInt32LittleEndian(ioctl, 44, 1);
            await Exchange(11, ioctl, 1, NtStatus.InvalidParameter);
            var directory = new byte[32];
            Wire.WriteUInt16LittleEndian(directory, 0, 33);
            Wire.WriteUInt32LittleEndian(directory, 28, 65537);
            await Exchange(14, directory, 2, NtStatus.InvalidParameter);
            var write = new byte[48];
            byte[] data = new byte[65537];
            new Random(897).NextBytes(data);
            Wire.WriteUInt16LittleEndian(write, 0, 49);
            Wire.WriteUInt16LittleEndian(write, 2, 112);
            Wire.WriteUInt32LittleEndian(write, 4, (uint)data.Length);
            opened.AsSpan(128, 16).CopyTo(write.AsSpan(16));
            var writeBody = Wire.Join(write, data);
            await Exchange(9, writeBody, 1, NtStatus.InvalidParameter);
            Check.Equal(0L, new FileInfo(path).Length, "undercharged write leaves file empty");
            await Exchange(9, writeBody, 2);
            var read = new byte[49];
            Wire.WriteUInt16LittleEndian(read, 0, 49);
            Wire.WriteUInt32LittleEndian(read, 4, (uint)data.Length);
            opened.AsSpan(128, 16).CopyTo(read.AsSpan(16));
            await Exchange(8, read, 1, NtStatus.InvalidParameter);
            Wire.WriteUInt32LittleEndian(read, 4, 1048577);
            await Exchange(8, read, 17, NtStatus.InvalidParameter);
            Wire.WriteUInt32LittleEndian(read, 4, (uint)data.Length);
            var reply = await Exchange(8, read, 2);
            Check.Bytes(data, reply[80..], "two-credit read payload");
            Wire.WriteUInt64LittleEndian(read, 8, 1);
            var shorter = await Exchange(8, read, 2);
            Check.Bytes(data[1..], shorter[80..], "short read excludes stale tail");
            Check.Bytes(data, reply[80..], "returned packet remains owned after next read");

            var replay = session.Request(13, [4, 0, 0, 0]);
            Wire.WriteUInt64LittleEndian(replay, 24, Wire.ReadUInt64LittleEndian(reply, 24) + 1);
            session.Crypto.Sign(replay);
            await Check.StatusAsync(NtStatus.InvalidParameter, () => session.Connection.ProcessAsync(replay).AsTask(), "interior MessageId cannot be reused");
            Console.WriteLine("PASS multi-credit file limits, contiguous MessageIds and payload validation");
        }
        finally { File.Delete(path); }
    }

    private sealed class Session : IAsyncDisposable
    {
        internal readonly ServerConnection Connection;
        internal SessionCrypto Crypto = null!;
        internal ulong SessionId;
        private ulong message;
        private uint tree;
        private readonly SmbServer server;
        internal byte[] Request(ushort cmd, byte[] body, ushort charge = 1)
        {
            var packet = Wire.Join(Wire.Header(cmd, message, SessionId, tree), body);
            Wire.WriteUInt16LittleEndian(packet, 6, charge);
            message += Math.Max(1u, charge);
            return packet;
        }
        private Session(string root)
        {
            server = new(new() { RootPath = root, UserName = "smbtest", Password = "testpass", Writable = true, RequireEncryption = false }); Connection = new(server);
        }
        internal static async Task<Session> CreateAsync(string root, bool multiCredit = false)
        {
            var session = new Session(root);
            try { await session.InitializeAsync(multiCredit); return session; }
            catch { await session.DisposeAsync(); throw; }
        }
        private async Task InitializeAsync(bool multiCredit)
        {
            var b = new byte[40]; Wire.WriteUInt16LittleEndian(b, 0, 36); Wire.WriteUInt16LittleEndian(b, 2, 1); Wire.WriteUInt16LittleEndian(b, 4, 3); Wire.WriteUInt32LittleEndian(b, 8, 0x40); Guid.NewGuid().ToByteArray().CopyTo(b, 12); Wire.WriteUInt32LittleEndian(b, 28, 104); Wire.WriteUInt16LittleEndian(b, 32, 3); Wire.WriteUInt16LittleEndian(b, 36, 0x311);
            if (multiCredit) Wire.WriteUInt32LittleEndian(b, 8, 0x44);
            var request = Request(0, Wire.Join(b, Negotiation.Contexts())); var response = await Connection.ProcessAsync(request); var hash = Negotiation.Hash(Negotiation.Hash(new byte[64], request), response);
            uint limit = multiCredit ? 1048576u : 65536u;
            Check.Equal(multiCredit, (Wire.ReadUInt32LittleEndian(response, 88) & 4) != 0, "negotiated Large MTU");
            Check.Equal(65536u, Wire.ReadUInt32LittleEndian(response, 92), "maximum transaction size");
            Check.Equal(limit, Wire.ReadUInt32LittleEndian(response, 96), "maximum read size");
            Check.Equal(limit, Wire.ReadUInt32LittleEndian(response, 100), "maximum write size");
            var ntlm = Ntlm.Negotiate();
            byte[] Setup(byte[] token) { var body = new byte[24]; Wire.WriteUInt16LittleEndian(body, 0, 25); body[3] = 3; Wire.WriteUInt16LittleEndian(body, 12, 88); Wire.WriteUInt16LittleEndian(body, 14, token.Length); return Request(1, Wire.Join(body, token)); }
            request = Setup(Spnego.Request(ntlm, true)); hash = Negotiation.Hash(hash, request); response = await Connection.ProcessAsync(request); hash = Negotiation.Hash(hash, response); SessionId = Wire.ReadUInt64LittleEndian(response, 40);
            var challenge = Spnego.Unwrap(Wire.Slice(response, Wire.ReadUInt16LittleEndian(response, 68), Wire.ReadUInt16LittleEndian(response, 70)).ToArray());
            var (token, key) = Ntlm.Authenticate(ntlm, challenge, "smbtest", "testpass", "WORKGROUP"); request = Setup(Spnego.Request(token, false)); hash = Negotiation.Hash(hash, request); response = await Connection.ProcessAsync(request);
            try { Crypto = new(key, hash, false); } finally { CryptographicOperations.ZeroMemory(key); }
            Crypto.Verify(response);
            var path = Encoding.Unicode.GetBytes("\\\\localhost\\files"); b = new byte[8]; Wire.WriteUInt16LittleEndian(b, 0, 9); Wire.WriteUInt16LittleEndian(b, 4, 72); Wire.WriteUInt16LittleEndian(b, 6, path.Length); request = Request(3, Wire.Join(b, path)); Crypto.Sign(request); response = await Connection.ProcessAsync(request); Crypto.Verify(response); tree = Wire.ReadUInt32LittleEndian(response, 36);
        }
        public async ValueTask DisposeAsync()
        {
            await Connection.DisposeAsync();
            Crypto?.Dispose();
            await server.DisposeAsync();
        }
    }
}
