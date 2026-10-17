using System.Security.Cryptography;
using System.Text;

namespace Tedd.Smb;

internal static class Spnego
{
    internal static readonly byte[] Initial = Convert.FromHexString("601C06062B0601050502A0123010A00E300C060A2B06010401823702020A");
    private static readonly byte[] Oid = Convert.FromHexString("060A2B06010401823702020A");
    internal static byte[] Wrap(byte tag, byte[] b) => Wire.Join(new[] { tag }, b.Length < 128 ? new[] { (byte)b.Length } : b.Length < 256 ? new byte[] { 0x81, (byte)b.Length } : new byte[] { 0x82, (byte)(b.Length >> 8), (byte)b.Length }, b);
    internal static byte[] Response(byte[] token, bool challenge) => Wrap(0xa1, Wrap(0x30, Wire.Join(Wrap(0xa0, new byte[] { 10, 1, challenge ? (byte)1 : (byte)0 }), challenge ? Wrap(0xa1, Oid) : [], token.Length == 0 ? [] : Wrap(0xa2, Wrap(4, token)))));
    internal static byte[] Request(byte[] token, bool initial) => initial
        ? Wrap(0x60, Wire.Join(Convert.FromHexString("06062B0601050502"), Wrap(0xa0, Wrap(0x30, Wire.Join(Wrap(0xa0, Wrap(0x30, Oid)), Wrap(0xa2, Wrap(4, token)))))))
        : Wrap(0xa1, Wrap(0x30, Wrap(0xa2, Wrap(4, token))));
    internal static byte[] Unwrap(byte[] b)
    {
        if (b.AsSpan().StartsWith("NTLMSSP\0"u8)) return b;
        byte[]? found = null;
        void Walk(ReadOnlySpan<byte> p, int depth)
        {
            if (depth > 10) throw new SmbException(Status.InvalidParameter);
            while (p.Length > 0)
            {
                if (p.Length < 2) throw new SmbException(Status.InvalidParameter);
                int tag = p[0], n = p[1], h = 2;
                if (n >= 128)
                {
                    int k = n & 127; n = 0;
                    if (k is 0 or > 2 || p.Length < 2 + k) throw new SmbException(Status.InvalidParameter);
                    for (int i = 0; i < k; i++) n = (n << 8) | p[h++];
                }
                var value = Wire.Slice(p, h, n);
                if (tag == 4 && value.StartsWith("NTLMSSP\0"u8)) { if (found != null) throw new SmbException(Status.InvalidParameter); found = value.ToArray(); }
                else if ((tag & 32) != 0) Walk(value, depth + 1);
                p = p[(h + n)..];
            }
        }
        Walk(b, 0); return found ?? throw new SmbException(Status.NotSupported);
    }
}

internal static class Ntlm
{
    internal const uint Flags = 0xe2088235;
    internal static void Sec(byte[] b, int p, byte[] value, int offset)
    {
        Wire.W16(b, p, value.Length); Wire.W16(b, p + 2, value.Length); Wire.W32(b, p + 4, (uint)offset); value.CopyTo(b, offset);
    }
    internal static byte[] Field(byte[] b, int p, int min)
    {
        int n = Wire.U16(b, p); uint o = Wire.U32(b, p + 4);
        if (o > int.MaxValue || (n > 0 && o < min)) throw new SmbException(Status.InvalidParameter);
        return Wire.Slice(b, (int)o, n).ToArray();
    }
    internal static byte[] Av(ushort id, byte[] value)
    {
        var b = new byte[4 + value.Length]; Wire.W16(b, 0, id); Wire.W16(b, 2, value.Length); value.CopyTo(b, 4); return b;
    }
    internal static byte[] Negotiate()
    {
        var b = new byte[40]; "NTLMSSP\0"u8.CopyTo(b); Wire.W32(b, 8, 1); Wire.W32(b, 12, Flags); b[32] = 10; b[39] = 15; return b;
    }
    internal static byte[] ResponseKey(string user, string password, string domain)
    {
        var hash = Crypto.Md4(Encoding.Unicode.GetBytes(password));
        try { return HMACMD5.HashData(hash, Encoding.Unicode.GetBytes(user.ToUpperInvariant() + domain)); }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }
    internal static (byte[] Token, byte[] Key) Authenticate(byte[] negotiate, byte[] challenge, string user, string password, string domain)
    {
        if (challenge.Length < 56 || Wire.U32(challenge, 8) != 2) throw new SmbException(Status.LogonFailure);
        uint flags = Wire.U32(challenge, 20) & Flags;
        var info = Field(challenge, 40, 48); byte[] timestamp = new byte[8]; Wire.W64(timestamp, 0, (ulong)DateTime.UtcNow.ToFileTimeUtc());
        var avs = new List<byte[]>(); int pos = 0;
        while (pos + 4 <= info.Length)
        {
            ushort id = Wire.U16(info, pos); int n = Wire.U16(info, pos + 2); var value = Wire.Slice(info, pos + 4, n).ToArray(); pos += 4 + n;
            if (id == 0) break;
            if (id == 7) timestamp = value;
            if (id != 6) avs.Add(Av(id, value));
        }
        avs.Add(Av(6, new byte[] { 2, 0, 0, 0 })); avs.Add(new byte[4]);
        var blob = Wire.Join(new byte[] { 1, 1, 0, 0, 0, 0, 0, 0 }, timestamp, RandomNumberGenerator.GetBytes(8), new byte[4], Wire.Join(avs.ToArray()), new byte[4]);
        var responseKey = ResponseKey(user, password, domain);
        var proof = HMACMD5.HashData(responseKey, Wire.Join(challenge[24..32], blob));
        var baseKey = HMACMD5.HashData(responseKey, proof);
        var key = (flags & 0x40000000) != 0 ? RandomNumberGenerator.GetBytes(16) : (byte[])baseKey.Clone();
        var fields = new[] { new byte[24], Wire.Join(proof, blob), Encoding.Unicode.GetBytes(domain), Encoding.Unicode.GetBytes(user), Encoding.Unicode.GetBytes("TEDDSMB"), (flags & 0x40000000) != 0 ? Crypto.Rc4(baseKey, key) : [] };
        int micAt = (flags & 0x02000000) != 0 ? 72 : 64, offset = micAt + 16;
        var b = new byte[offset + fields.Sum(x => x.Length)]; "NTLMSSP\0"u8.CopyTo(b); Wire.W32(b, 8, 3); Wire.W32(b, 60, flags);
        if (micAt == 72) { b[64] = 10; b[71] = 15; }
        for (int i = 0; i < fields.Length; i++) { Sec(b, 12 + i * 8, fields[i], offset); offset += fields[i].Length; }
        HMACMD5.HashData(key, Wire.Join(negotiate, challenge, b)).CopyTo(b, micAt);
        CryptographicOperations.ZeroMemory(responseKey); CryptographicOperations.ZeroMemory(baseKey); return (b, key);
    }
}

internal sealed class NtlmServer
{
    private readonly string user, password;
    private byte[] negotiate = [], challenge = [];
    private bool used;
    internal NtlmServer(string user, string password) { this.user = user; this.password = password; }
    internal byte[] Challenge(byte[] token)
    {
        if (negotiate.Length != 0 || token.Length < 32 || Wire.U32(token, 8) != 1) throw new SmbException(Status.LogonFailure);
        negotiate = token; uint flags = (Wire.U32(token, 12) & 0xe2088235) | 0x00828005;
        if ((flags & 0x00080201) != 0x00080201) throw new SmbException(Status.NotSupported);
        var time = new byte[8]; Wire.W64(time, 0, (ulong)DateTime.UtcNow.ToFileTimeUtc());
        var name = Encoding.Unicode.GetBytes("TEDDSMB");
        var info = Wire.Join(Ntlm.Av(1, name), Ntlm.Av(2, Encoding.Unicode.GetBytes("WORKGROUP")), Ntlm.Av(3, Encoding.Unicode.GetBytes(Environment.MachineName)), Ntlm.Av(7, time), new byte[4]);
        challenge = new byte[56 + name.Length + info.Length]; "NTLMSSP\0"u8.CopyTo(challenge); Wire.W32(challenge, 8, 2); Wire.W32(challenge, 20, flags);
        RandomNumberGenerator.Fill(challenge.AsSpan(24, 8)); challenge[48] = 10; challenge[55] = 15;
        Ntlm.Sec(challenge, 12, name, 56); Ntlm.Sec(challenge, 40, info, 56 + name.Length); return challenge;
    }
    internal byte[] Authenticate(byte[] token)
    {
        if (used || challenge.Length == 0 || token.Length < 64 || Wire.U32(token, 8) != 3) throw new SmbException(Status.LogonFailure);
        used = true; uint flags = Wire.U32(token, 60); int micAt = (flags & 0x02000000) != 0 ? 72 : 64;
        var nt = Ntlm.Field(token, 20, micAt); var domain = Ntlm.Field(token, 28, micAt); var username = Ntlm.Field(token, 36, micAt); var enc = Ntlm.Field(token, 52, micAt);
        if (!Wire.Text(username).Equals(user, StringComparison.OrdinalIgnoreCase) || nt.Length < 48 || nt[16] != 1 || nt[17] != 1 || Wire.U16(nt, 18) != 0 || Wire.U32(nt, 20) != 0 || Wire.U32(nt, 40) != 0)
            throw new SmbException(Status.LogonFailure);
        if ((flags & 0x40080211) != (Wire.U32(challenge, 20) & 0x40080211)) throw new SmbException(Status.LogonFailure);
        long timestamp = checked((long)Wire.U64(nt, 24));
        if (Math.Abs(DateTime.UtcNow.ToFileTimeUtc() - timestamp) > TimeSpan.FromMinutes(5).Ticks) throw new SmbException(Status.LogonFailure);
        bool mic = false, ended = false;
        for (int p = 44; p + 4 <= nt.Length;)
        {
            ushort id = Wire.U16(nt, p); int n = Wire.U16(nt, p + 2); var value = Wire.Slice(nt, p + 4, n); p += 4 + n;
            if (id == 0) { if (n != 0) throw new SmbException(Status.LogonFailure); ended = true; break; }
            if (id == 6) { if (n != 4) throw new SmbException(Status.LogonFailure); mic = (Wire.U32(value, 0) & 2) != 0; }
        }
        if (!ended) throw new SmbException(Status.LogonFailure);
        var responseKey = Ntlm.ResponseKey(user, password, Wire.Text(domain));
        try
        {
            var proof = HMACMD5.HashData(responseKey, Wire.Join(challenge[24..32], nt[16..]));
            if (!CryptographicOperations.FixedTimeEquals(proof, nt.AsSpan(0, 16))) throw new SmbException(Status.LogonFailure);
            var baseKey = HMACMD5.HashData(responseKey, proof);
            byte[] key;
            try { key = (flags & 0x40000000) != 0 ? enc.Length == 16 ? Crypto.Rc4(baseKey, enc) : throw new SmbException(Status.LogonFailure) : enc.Length == 0 ? (byte[])baseKey.Clone() : throw new SmbException(Status.LogonFailure); }
            finally { CryptographicOperations.ZeroMemory(baseKey); }
            if (mic)
            {
                var signature = Wire.Slice(token, micAt, 16).ToArray(); var copy = (byte[])token.Clone(); copy.AsSpan(micAt, 16).Clear();
                for (int p = 12; p <= 52; p += 8) _ = Ntlm.Field(token, p, micAt + 16);
                if (!CryptographicOperations.FixedTimeEquals(signature, HMACMD5.HashData(key, Wire.Join(negotiate, challenge, copy)))) { CryptographicOperations.ZeroMemory(key); throw new SmbException(Status.LogonFailure); }
            }
            return key;
        }
        finally { CryptographicOperations.ZeroMemory(responseKey); }
    }
}
