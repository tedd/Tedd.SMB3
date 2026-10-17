using System.Security.Cryptography;
using System.Text;
using Tedd.Smb;

internal static class ProtocolChecks
{
    internal static void Run(string root)
    {
        void Rejected(Action action, string label)
        {
            try { action(); } catch (Exception e) when (e is SmbException or CryptographicException or ArgumentException) { Console.WriteLine("PASS " + label); return; }
            throw new Exception("Accepted invalid request: " + label);
        }
        using (var s = new Session(root))
        {
            var p = s.Request(13, [4, 0, 0, 0]); s.Crypto.Sign(p); _ = s.Connection.Process(p);
            Rejected(() => s.Connection.Process(p), "signed message replay rejected");
        }
        using (var s = new Session(root))
        {
            var p = s.Crypto.Encrypt(s.Request(13, [4, 0, 0, 0]), s.SessionId); _ = s.Connection.Process(p);
            Rejected(() => s.Connection.Process(p), "encrypted message replay rejected");
        }
        using (var s = new Session(root))
        { var p = s.Request(13, [4, 0, 0, 0]); s.Crypto.Sign(p); p[^1] ^= 1; Rejected(() => s.Connection.Process(p), "altered signed command rejected"); }
        using (var s = new Session(root))
        { var p = s.Request(13, [4, 0, 0, 0]); Rejected(() => s.Connection.Process(p), "unsigned authenticated command rejected"); }
        using (var s = new Session(root))
        { var p = s.Request(13, [4, 0, 0, 0]); Wire.W32(p, 20, 65); Rejected(() => s.Connection.Process(p), "unaligned compound rejected"); }
        using (var s = new Session(root))
        {
            var cancel = s.Request(12, [4, 0, 0, 0]); Wire.W64(cancel, 24, 1); s.Crypto.Sign(cancel);
            if (s.Connection.Process(cancel).Length != 0) throw new Exception("CANCEL generated a reply.");
            var echo = s.Request(13, [4, 0, 0, 0]); s.Crypto.Sign(echo); var reply = s.Connection.Process(echo); s.Crypto.Verify(reply);
            Console.WriteLine("PASS completed-request CANCEL has no reply and preserves connection");
        }
        foreach (bool encrypt in new[] { false, true })
        using (var s = new Session(root))
        {
            var path = Encoding.Unicode.GetBytes("compound-" + Guid.NewGuid().ToString("N"));
            var create = new byte[56]; Wire.W16(create, 0, 57); Wire.W32(create, 24, 0x13019f); Wire.W32(create, 32, 7); Wire.W32(create, 36, 2); Wire.W32(create, 40, 0x40); Wire.W16(create, 44, 120); Wire.W16(create, 46, path.Length);
            var payload = Encoding.UTF8.GetBytes("compound write payload"); var write = new byte[48]; Wire.W16(write, 0, 49); Wire.W16(write, 2, 112); Wire.W32(write, 4, (uint)payload.Length); write.AsSpan(16, 16).Fill(255);
            var close = new byte[24]; Wire.W16(close, 0, 24); close.AsSpan(8, 16).Fill(255);
            var packets = new[] { s.Request(5, Wire.Join(create, path)), s.Request(9, Wire.Join(write, payload)), s.Request(6, close) };
            for (int i = 0; i < packets.Length; i++)
            {
                if (i > 0) { Wire.W32(packets[i], 16, 4); Wire.W32(packets[i], 36, uint.MaxValue); Wire.W64(packets[i], 40, ulong.MaxValue); }
                if (i < packets.Length - 1) { var p = packets[i]; Array.Resize(ref p, Wire.Align(p.Length)); Wire.W32(p, 20, (uint)p.Length); packets[i] = p; }
                if (!encrypt) s.Crypto.Sign(packets[i]);
            }
            var request = Wire.Join(packets); var response = s.Connection.Process(encrypt ? s.Crypto.Encrypt(request, s.SessionId) : request);
            if (encrypt) response = s.Crypto.Decrypt(response, s.SessionId);
            int offset = 0;
            for (int i = 0; i < packets.Length; i++)
            {
                int next = checked((int)Wire.U32(response, offset + 20)); var part = response.AsSpan(offset, next == 0 ? response.Length - offset : next).ToArray();
                if (!encrypt) s.Crypto.Verify(part);
                if (Wire.U32(part, 8) != 0) throw new Exception("Compound failed."); offset += part.Length;
            }
            string file = Path.Combine(root, Encoding.Unicode.GetString(path));
            if (!File.ReadAllBytes(file).AsSpan().SequenceEqual(payload)) throw new Exception("Compound data mismatch."); File.Delete(file);
            Console.WriteLine($"PASS related CREATE/WRITE/CLOSE compound encrypted={encrypt}");
        }
    }
    private sealed class Session : IDisposable
    {
        internal readonly ServerConnection Connection;
        internal readonly SessionCrypto Crypto;
        internal ulong SessionId;
        private ulong message;
        private uint tree;
        private readonly SmbServer server;
        internal byte[] Request(ushort cmd, byte[] body) => Wire.Join(Wire.Header(cmd, message++, SessionId, tree), body);
        internal Session(string root)
        {
            server = new(new() { RootPath = root, UserName = "smbtest", Password = "testpass", Writable = true, RequireEncryption = false }); Connection = new(server);
            var b = new byte[40]; Wire.W16(b, 0, 36); Wire.W16(b, 2, 1); Wire.W16(b, 4, 3); Wire.W32(b, 8, 0x40); Guid.NewGuid().ToByteArray().CopyTo(b, 12); Wire.W32(b, 28, 104); Wire.W16(b, 32, 3); Wire.W16(b, 36, 0x311);
            var request = Request(0, Wire.Join(b, Negotiation.Contexts())); var response = Connection.Process(request); var hash = Negotiation.Hash(Negotiation.Hash(new byte[64], request), response);
            var ntlm = Ntlm.Negotiate();
            byte[] Setup(byte[] token) { var body = new byte[24]; Wire.W16(body, 0, 25); body[3] = 3; Wire.W16(body, 12, 88); Wire.W16(body, 14, token.Length); return Request(1, Wire.Join(body, token)); }
            request = Setup(Spnego.Request(ntlm, true)); hash = Negotiation.Hash(hash, request); response = Connection.Process(request); hash = Negotiation.Hash(hash, response); SessionId = Wire.U64(response, 40);
            var challenge = Spnego.Unwrap(Wire.Slice(response, Wire.U16(response, 68), Wire.U16(response, 70)).ToArray());
            var (token, key) = Ntlm.Authenticate(ntlm, challenge, "smbtest", "testpass", "WORKGROUP"); request = Setup(Spnego.Request(token, false)); hash = Negotiation.Hash(hash, request); response = Connection.Process(request);
            try { Crypto = new(key, hash, false); } finally { CryptographicOperations.ZeroMemory(key); } Crypto.Verify(response);
            var path = Encoding.Unicode.GetBytes("\\\\localhost\\files"); b = new byte[8]; Wire.W16(b, 0, 9); Wire.W16(b, 4, 72); Wire.W16(b, 6, path.Length); request = Request(3, Wire.Join(b, path)); Crypto.Sign(request); response = Connection.Process(request); Crypto.Verify(response); tree = Wire.U32(response, 36);
        }
        public void Dispose() { Connection.Dispose(); Crypto.Dispose(); server.DisposeAsync().AsTask().GetAwaiter().GetResult(); }
    }
}
