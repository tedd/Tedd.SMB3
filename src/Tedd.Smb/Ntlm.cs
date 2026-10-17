using System.Security.Cryptography;
using System.Text;

namespace Tedd.Smb;

internal static class Spnego
{
    internal static readonly byte[] Initial = Convert.FromHexString("601C06062B0601050502A0123010A00E300C060A2B06010401823702020A");
    private static readonly byte[] Oid = Convert.FromHexString("060A2B06010401823702020A");
    internal static byte[] Wrap(byte tag, byte[] b) => Wire.Join(new[] { tag }, b.Length < 128 ? new[] { (byte)b.Length } : b.Length < 256 ? new byte[] { 0x81, (byte)b.Length } : new byte[] { 0x82, (byte)(b.Length >> 8), (byte)b.Length }, b);
    internal static byte[] Response(byte[] token, bool challenge) => Wrap(SpnegoTag.NegTokenResp, Wrap(Asn1Tag.Sequence, Wire.Join(
        Wrap(SpnegoTag.NegState, new byte[] { Asn1Tag.Enumerated, sizeof(byte), challenge ? SpnegoNegState.AcceptIncomplete : SpnegoNegState.AcceptCompleted }),
        challenge ? Wrap(SpnegoTag.SupportedMech, Oid) : [],
        token.Length == 0 ? [] : Wrap(SpnegoTag.ResponseToken, Wrap(Asn1Tag.OctetString, token)))));
    internal static byte[] Request(byte[] token, bool initial) => initial
        ? Wrap(SpnegoTag.InitialContextToken, Wire.Join(Convert.FromHexString("06062B0601050502"),
            Wrap(SpnegoTag.NegTokenInit, Wrap(Asn1Tag.Sequence, Wire.Join(
                Wrap(SpnegoTag.MechTypes, Wrap(Asn1Tag.Sequence, Oid)), Wrap(SpnegoTag.MechToken, Wrap(Asn1Tag.OctetString, token)))))))
        : Wrap(SpnegoTag.NegTokenResp, Wrap(Asn1Tag.Sequence, Wrap(SpnegoTag.ResponseToken, Wrap(Asn1Tag.OctetString, token))));
    internal static byte[] Unwrap(byte[] b)
    {
        if (b.AsSpan().StartsWith(NtlmMessage.Signature)) return b;
        byte[]? found = null;
        void Walk(ReadOnlySpan<byte> p, int depth)
        {
            if (depth > 10) throw new SmbException(NtStatus.InvalidParameter);
            while (p.Length > 0)
            {
                if (p.Length < 2) throw new SmbException(NtStatus.InvalidParameter);
                int tag = p[0], n = p[1], h = 2;
                if (n >= 128)
                {
                    int k = n & 127; n = 0;
                    if (k is 0 or > 2 || p.Length < 2 + k) throw new SmbException(NtStatus.InvalidParameter);
                    for (int i = 0; i < k; i++) n = (n << 8) | p[h++];
                }
                var value = Wire.Slice(p, h, n);
                if (tag == Asn1Tag.OctetString && value.StartsWith(NtlmMessage.Signature)) { if (found != null) throw new SmbException(NtStatus.InvalidParameter); found = value.ToArray(); }
                else if ((tag & Asn1Tag.Constructed) != 0) Walk(value, depth + 1);
                p = p[(h + n)..];
            }
        }
        Walk(b, 0); return found ?? throw new SmbException(NtStatus.NotSupported);
    }
}

internal static class Ntlm
{
    internal static void WriteSecurityBuffer(byte[] b, int p, byte[] value, int offset)
    {
        Wire.WriteUInt16LittleEndian(b, p, value.Length);
        Wire.WriteUInt16LittleEndian(b, p + NtlmSecurityBuffer.MaximumLengthOffset, value.Length);
        Wire.WriteUInt32LittleEndian(b, p + NtlmSecurityBuffer.BufferOffset, (uint)offset); value.CopyTo(b, offset);
    }
    internal static byte[] ReadSecurityBuffer(byte[] b, int p, int min)
    {
        int n = Wire.ReadUInt16LittleEndian(b, p); uint o = Wire.ReadUInt32LittleEndian(b, p + NtlmSecurityBuffer.BufferOffset);
        if (o > int.MaxValue || (n > 0 && o < min)) throw new SmbException(NtStatus.InvalidParameter);
        return Wire.Slice(b, (int)o, n).ToArray();
    }
    internal static byte[] WriteAvPair(ushort id, byte[] value)
    {
        var b = new byte[NtlmAvPair.HeaderSize + value.Length];
        Wire.WriteUInt16LittleEndian(b, NtlmAvPair.AvIdOffset, id);
        Wire.WriteUInt16LittleEndian(b, NtlmAvPair.AvLenOffset, value.Length); value.CopyTo(b, NtlmAvPair.HeaderSize); return b;
    }
    internal static byte[] Negotiate()
    {
        var b = new byte[NtlmNegotiateMessage.SizeWithVersion]; NtlmMessage.Signature.CopyTo(b);
        Wire.WriteUInt32LittleEndian(b, NtlmMessage.MessageTypeOffset, NtlmMessageType.Negotiate);
        Wire.WriteUInt32LittleEndian(b, NtlmNegotiateMessage.NegotiateFlagsOffset, NtlmNegotiateFlags.Supported); b[NtlmNegotiateMessage.VersionOffset + NtlmVersion.ProductMajorVersionOffset] = NtlmVersion.Windows10MajorVersion; b[NtlmNegotiateMessage.VersionOffset + NtlmVersion.NtlmRevisionCurrentOffset] = NtlmVersion.RevisionW2k3; return b;
    }
    internal static byte[] ResponseKey(string user, string password, string domain)
    {
        var hash = Crypto.Md4(Encoding.Unicode.GetBytes(password));
        try { return HMACMD5.HashData(hash, Encoding.Unicode.GetBytes(user.ToUpperInvariant() + domain)); }
        finally { CryptographicOperations.ZeroMemory(hash); }
    }
    internal static (byte[] Token, byte[] Key) Authenticate(byte[] negotiate, byte[] challenge, string user, string password, string domain)
    {
        if (challenge.Length < NtlmChallengeMessage.SizeWithVersion || Wire.ReadUInt32LittleEndian(challenge, NtlmMessage.MessageTypeOffset) != NtlmMessageType.Challenge) throw new SmbException(NtStatus.LogonFailure);
        uint flags = Wire.ReadUInt32LittleEndian(challenge, NtlmChallengeMessage.NegotiateFlagsOffset) & NtlmNegotiateFlags.Supported;
        var info = ReadSecurityBuffer(challenge, NtlmChallengeMessage.TargetInfoFieldsOffset, NtlmChallengeMessage.FixedSize); byte[] timestamp = new byte[NtlmMessage.TimestampSize];
        Wire.WriteUInt64LittleEndian(timestamp, 0, (ulong)DateTime.UtcNow.ToFileTimeUtc());
        var avs = new List<byte[]>(); int pos = 0;
        while (pos + NtlmAvPair.HeaderSize <= info.Length)
        {
            ushort id = Wire.ReadUInt16LittleEndian(info, pos); int n = Wire.ReadUInt16LittleEndian(info, pos + NtlmAvPair.AvLenOffset); var value = Wire.Slice(info, pos + NtlmAvPair.HeaderSize, n).ToArray(); pos += NtlmAvPair.HeaderSize + n;
            if (id == NtlmAvId.Eol) break;
            if (id == NtlmAvId.Timestamp) timestamp = value;
            if (id != NtlmAvId.Flags) avs.Add(WriteAvPair(id, value));
        }
        var avFlags = new byte[sizeof(uint)];
        Wire.WriteUInt32LittleEndian(avFlags, 0, NtlmAvFlags.MicPresent); avs.Add(WriteAvPair(NtlmAvId.Flags, avFlags)); avs.Add(new byte[NtlmAvPair.HeaderSize]);
        var blob = Wire.Join(new byte[] { 1, 1, 0, 0, 0, 0, 0, 0 }, timestamp, RandomNumberGenerator.GetBytes(NtlmMessage.ChallengeSize), new byte[NtlmAvPair.HeaderSize], Wire.Join(avs.ToArray()), new byte[NtlmAvPair.HeaderSize]);
        var responseKey = ResponseKey(user, password, domain);
        var proof = HMACMD5.HashData(responseKey, Wire.Join(challenge[NtlmChallengeMessage.ServerChallengeOffset..(NtlmChallengeMessage.ServerChallengeOffset + NtlmMessage.ChallengeSize)], blob));
        var baseKey = HMACMD5.HashData(responseKey, proof);
        var key = (flags & NtlmNegotiateFlags.KeyExchange) != 0 ? RandomNumberGenerator.GetBytes(NtlmMessage.SessionKeySize) : (byte[])baseKey.Clone();
        var fields = new[] { new byte[NtlmMessage.LmResponseSize], Wire.Join(proof, blob), Encoding.Unicode.GetBytes(domain), Encoding.Unicode.GetBytes(user), Encoding.Unicode.GetBytes("TEDDSMB"), (flags & NtlmNegotiateFlags.KeyExchange) != 0 ? Crypto.Rc4(baseKey, key) : [] };
        int micAt = (flags & NtlmNegotiateFlags.Version) != 0 ? NtlmAuthenticateMessage.SizeWithVersion : NtlmAuthenticateMessage.FixedSize, offset = micAt + NtlmMessage.MicSize;
        var b = new byte[offset + fields.Sum(x => x.Length)]; NtlmMessage.Signature.CopyTo(b);
        Wire.WriteUInt32LittleEndian(b, NtlmMessage.MessageTypeOffset, NtlmMessageType.Authenticate);
        Wire.WriteUInt32LittleEndian(b, NtlmAuthenticateMessage.NegotiateFlagsOffset, flags);
        if (micAt == NtlmAuthenticateMessage.SizeWithVersion) { b[NtlmAuthenticateMessage.VersionOffset + NtlmVersion.ProductMajorVersionOffset] = NtlmVersion.Windows10MajorVersion; b[NtlmAuthenticateMessage.VersionOffset + NtlmVersion.NtlmRevisionCurrentOffset] = NtlmVersion.RevisionW2k3; }
        for (int i = 0; i < fields.Length; i++) { WriteSecurityBuffer(b, NtlmAuthenticateMessage.LmChallengeResponseFieldsOffset + i * NtlmSecurityBuffer.Size, fields[i], offset); offset += fields[i].Length; }
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
        if (negotiate.Length != 0 || token.Length < NtlmNegotiateMessage.FixedSize || Wire.ReadUInt32LittleEndian(token, NtlmMessage.MessageTypeOffset) != NtlmMessageType.Negotiate) throw new SmbException(NtStatus.LogonFailure);
        negotiate = token; uint flags = (Wire.ReadUInt32LittleEndian(token, NtlmNegotiateMessage.NegotiateFlagsOffset) & NtlmNegotiateFlags.Supported) | NtlmNegotiateFlags.ServerChallenge;
        if ((flags & NtlmNegotiateFlags.Required) != NtlmNegotiateFlags.Required) throw new SmbException(NtStatus.NotSupported);
        var time = new byte[NtlmMessage.TimestampSize];
        Wire.WriteUInt64LittleEndian(time, 0, (ulong)DateTime.UtcNow.ToFileTimeUtc());
        var name = Encoding.Unicode.GetBytes("TEDDSMB");
        var info = Wire.Join(Ntlm.WriteAvPair(NtlmAvId.NbComputerName, name), Ntlm.WriteAvPair(NtlmAvId.NbDomainName, Encoding.Unicode.GetBytes("WORKGROUP")), Ntlm.WriteAvPair(NtlmAvId.DnsComputerName, Encoding.Unicode.GetBytes(Environment.MachineName)), Ntlm.WriteAvPair(NtlmAvId.Timestamp, time), new byte[NtlmAvPair.HeaderSize]);
        challenge = new byte[NtlmChallengeMessage.SizeWithVersion + name.Length + info.Length]; NtlmMessage.Signature.CopyTo(challenge);
        Wire.WriteUInt32LittleEndian(challenge, NtlmMessage.MessageTypeOffset, NtlmMessageType.Challenge);
        Wire.WriteUInt32LittleEndian(challenge, NtlmChallengeMessage.NegotiateFlagsOffset, flags);
        RandomNumberGenerator.Fill(challenge.AsSpan(NtlmChallengeMessage.ServerChallengeOffset, NtlmMessage.ChallengeSize)); challenge[NtlmChallengeMessage.VersionOffset + NtlmVersion.ProductMajorVersionOffset] = NtlmVersion.Windows10MajorVersion; challenge[NtlmChallengeMessage.VersionOffset + NtlmVersion.NtlmRevisionCurrentOffset] = NtlmVersion.RevisionW2k3;
        Ntlm.WriteSecurityBuffer(challenge, NtlmChallengeMessage.TargetNameFieldsOffset, name, NtlmChallengeMessage.SizeWithVersion); Ntlm.WriteSecurityBuffer(challenge, NtlmChallengeMessage.TargetInfoFieldsOffset, info, NtlmChallengeMessage.SizeWithVersion + name.Length); return challenge;
    }
    internal byte[] Authenticate(byte[] token)
    {
        if (used || challenge.Length == 0 || token.Length < NtlmAuthenticateMessage.FixedSize || Wire.ReadUInt32LittleEndian(token, NtlmMessage.MessageTypeOffset) != NtlmMessageType.Authenticate) throw new SmbException(NtStatus.LogonFailure);
        used = true; uint flags = Wire.ReadUInt32LittleEndian(token, NtlmAuthenticateMessage.NegotiateFlagsOffset); int micAt = (flags & NtlmNegotiateFlags.Version) != 0 ? NtlmAuthenticateMessage.SizeWithVersion : NtlmAuthenticateMessage.FixedSize;
        var nt = Ntlm.ReadSecurityBuffer(token, NtlmAuthenticateMessage.NtChallengeResponseFieldsOffset, micAt); var domain = Ntlm.ReadSecurityBuffer(token, NtlmAuthenticateMessage.DomainNameFieldsOffset, micAt); var username = Ntlm.ReadSecurityBuffer(token, NtlmAuthenticateMessage.UserNameFieldsOffset, micAt); var enc = Ntlm.ReadSecurityBuffer(token, NtlmAuthenticateMessage.EncryptedRandomSessionKeyFieldsOffset, micAt);
        if (!Wire.Text(username).Equals(user, StringComparison.OrdinalIgnoreCase) || nt.Length < NtlmV2Response.MinimumSize || nt[NtlmV2Response.ResponseTypeOffset] != NtlmV2Response.ResponseVersion || nt[NtlmV2Response.HiResponseTypeOffset] != NtlmV2Response.ResponseVersion || Wire.ReadUInt16LittleEndian(nt, NtlmV2Response.Reserved1Offset) != 0 || Wire.ReadUInt32LittleEndian(nt, NtlmV2Response.Reserved2Offset) != 0 || Wire.ReadUInt32LittleEndian(nt, NtlmV2Response.Reserved3Offset) != 0)
            throw new SmbException(NtStatus.LogonFailure);
        if ((flags & NtlmNegotiateFlags.AuthenticateConsistencyMask) != (Wire.ReadUInt32LittleEndian(challenge, NtlmChallengeMessage.NegotiateFlagsOffset) & NtlmNegotiateFlags.AuthenticateConsistencyMask)) throw new SmbException(NtStatus.LogonFailure);
        long timestamp = checked((long)Wire.ReadUInt64LittleEndian(nt, NtlmV2Response.TimestampOffset));
        if (Math.Abs(DateTime.UtcNow.ToFileTimeUtc() - timestamp) > TimeSpan.FromMinutes(5).Ticks) throw new SmbException(NtStatus.LogonFailure);
        bool mic = false, ended = false;
        for (int p = NtlmV2Response.AvPairsOffset; p + NtlmAvPair.HeaderSize <= nt.Length;)
        {
            ushort id = Wire.ReadUInt16LittleEndian(nt, p); int n = Wire.ReadUInt16LittleEndian(nt, p + NtlmAvPair.AvLenOffset); var value = Wire.Slice(nt, p + NtlmAvPair.HeaderSize, n); p += NtlmAvPair.HeaderSize + n;
            if (id == NtlmAvId.Eol) { if (n != 0) throw new SmbException(NtStatus.LogonFailure); ended = true; break; }
            if (id == NtlmAvId.Flags) { if (n != sizeof(uint)) throw new SmbException(NtStatus.LogonFailure); mic = (Wire.ReadUInt32LittleEndian(value, 0) & NtlmAvFlags.MicPresent) != 0; }
        }
        if (!ended) throw new SmbException(NtStatus.LogonFailure);
        var responseKey = Ntlm.ResponseKey(user, password, Wire.Text(domain));
        try
        {
            var proof = HMACMD5.HashData(responseKey, Wire.Join(challenge[NtlmChallengeMessage.ServerChallengeOffset..(NtlmChallengeMessage.ServerChallengeOffset + NtlmMessage.ChallengeSize)], nt[NtlmV2Response.ProofSize..]));
            if (!CryptographicOperations.FixedTimeEquals(proof, nt.AsSpan(0, NtlmV2Response.ProofSize))) throw new SmbException(NtStatus.LogonFailure);
            var baseKey = HMACMD5.HashData(responseKey, proof);
            byte[] key;
            try { key = (flags & NtlmNegotiateFlags.KeyExchange) != 0 ? enc.Length == NtlmMessage.SessionKeySize ? Crypto.Rc4(baseKey, enc) : throw new SmbException(NtStatus.LogonFailure) : enc.Length == 0 ? (byte[])baseKey.Clone() : throw new SmbException(NtStatus.LogonFailure); }
            finally { CryptographicOperations.ZeroMemory(baseKey); }
            if (mic)
            {
                var signature = Wire.Slice(token, micAt, NtlmMessage.MicSize).ToArray(); var copy = (byte[])token.Clone(); copy.AsSpan(micAt, NtlmMessage.MicSize).Clear();
                for (int p = NtlmAuthenticateMessage.LmChallengeResponseFieldsOffset; p <= NtlmAuthenticateMessage.EncryptedRandomSessionKeyFieldsOffset; p += NtlmSecurityBuffer.Size) _ = Ntlm.ReadSecurityBuffer(token, p, micAt + NtlmMessage.MicSize);
                if (!CryptographicOperations.FixedTimeEquals(signature, HMACMD5.HashData(key, Wire.Join(negotiate, challenge, copy)))) { CryptographicOperations.ZeroMemory(key); throw new SmbException(NtStatus.LogonFailure); }
            }
            return key;
        }
        finally { CryptographicOperations.ZeroMemory(responseKey); }
    }
}
