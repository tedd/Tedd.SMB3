using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Tedd.Smb;

internal static class Crypto
{
    // RFC 1320. MD4 is used only for the NT password hash required by NTLMv2.
    internal static byte[] Md4(byte[] input)
    {
        var b = new byte[((input.Length + 9 + 63) / 64) * 64]; input.CopyTo(b, 0); b[input.Length] = 0x80;
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(b.Length - 8), (ulong)input.Length * 8);
        uint a = 0x67452301, c = 0x98badcfe, d = 0x10325476, v = 0xefcdab89;
        var x = new uint[16];
        foreach (var offset in Enumerable.Range(0, b.Length / 64).Select(i => i * 64))
        {
            for (int i = 0; i < 16; i++) x[i] = Wire.ReadUInt32LittleEndian(b, offset + i * 4);
            uint aa = a, bb = v, cc = c, dd = d;
            for (int round = 0; round < 3; round++)
                for (int i = 0; i < 16; i++)
                {
                    int k = round switch { 0 => i, 1 => (i % 4) * 4 + i / 4, _ => new[] { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 }[i] };
                    int s = (round switch { 0 => new[] { 3, 7, 11, 19 }, 1 => new[] { 3, 5, 9, 13 }, _ => new[] { 3, 9, 11, 15 } })[i % 4];
                    uint f = round switch { 0 => (v & c) | (~v & d), 1 => (v & c) | (v & d) | (c & d), _ => v ^ c ^ d };
                    uint z = BitOperations.RotateLeft(unchecked(a + f + x[k] + (round switch { 1 => 0x5a827999u, 2 => 0x6ed9eba1u, _ => 0u })), s);
                    a = d; d = c; c = v; v = z;
                }
            a = unchecked(a + aa); v = unchecked(v + bb); c = unchecked(c + cc); d = unchecked(d + dd);
        }
        var result = new byte[16];
        Wire.WriteUInt32LittleEndian(result, 0, a);
        Wire.WriteUInt32LittleEndian(result, 4, v);
        Wire.WriteUInt32LittleEndian(result, 8, c);
        Wire.WriteUInt32LittleEndian(result, 12, d);
        CryptographicOperations.ZeroMemory(b); return result;
    }
    internal static byte[] Rc4(byte[] key, byte[] data)
    {
        var s = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray(); int j = 0;
        for (int i = 0; i < 256; i++) { j = (j + s[i] + key[i % key.Length]) & 255; (s[i], s[j]) = (s[j], s[i]); }
        var result = new byte[data.Length]; int a = 0; j = 0;
        for (int k = 0; k < data.Length; k++) { a = (a + 1) & 255; j = (j + s[a]) & 255; (s[a], s[j]) = (s[j], s[a]); result[k] = (byte)(data[k] ^ s[(s[a] + s[j]) & 255]); }
        CryptographicOperations.ZeroMemory(s); return result;
    }
    internal static byte[] Kdf(byte[] key, string label, byte[] context)
    {
        // SP800-108 counter mode, label includes its protocol-specified NUL.
        var b = Wire.Join(new byte[] { 0, 0, 0, 1 }, Encoding.ASCII.GetBytes(label + "\0"), new byte[1], context, new byte[] { 0, 0, 0, 128 });
        return HMACSHA256.HashData(key, b)[..16];
    }
    internal static byte[] Cmac(byte[] key, byte[] message)
    {
        using var aes = Aes.Create(); aes.Key = key;
        byte[] Encrypt(byte[] b) => aes.EncryptEcb(b, PaddingMode.None);
        static byte[] Double(byte[] b)
        {
            var r = new byte[16]; int carry = 0;
            for (int i = 15; i >= 0; i--) { r[i] = (byte)((b[i] << 1) | carry); carry = b[i] >> 7; }
            if (carry != 0) r[15] ^= 0x87; return r;
        }
        var k1 = Double(Encrypt(new byte[16])); var k2 = Double(k1); var state = new byte[16];
        int blocks = Math.Max(1, (message.Length + 15) / 16);
        for (int i = 0; i < blocks; i++)
        {
            var block = new byte[16]; int n = Math.Min(16, message.Length - i * 16);
            if (n > 0) message.AsSpan(i * 16, n).CopyTo(block);
            if (i == blocks - 1)
            {
                var sub = n == 16 ? k1 : k2; if (n < 16) block[n] = 0x80;
                for (int k = 0; k < 16; k++) block[k] ^= sub[k];
            }
            for (int k = 0; k < 16; k++) block[k] ^= state[k]; state = Encrypt(block);
        }
        return state;
    }
}

internal sealed class SessionCrypto : IDisposable
{
    private readonly byte[] signing, outgoing, incoming;
    private readonly byte[] noncePrefix = RandomNumberGenerator.GetBytes(Smb3Cryptography.GcmNonceSize - Smb3Cryptography.NonceCounterSize);
    private ulong nonce;
    private readonly int cipher;
    internal SessionCrypto(byte[] sessionKey, byte[] preauth, bool server, int cipher = Smb2Cipher.Aes128Gcm)
    {
        this.cipher = cipher;
        signing = Crypto.Kdf(sessionKey, Smb3Cryptography.SigningKeyLabel, preauth);
        outgoing = Crypto.Kdf(sessionKey, server ? Smb3Cryptography.ServerToClientCipherKeyLabel : Smb3Cryptography.ClientToServerCipherKeyLabel, preauth);
        incoming = Crypto.Kdf(sessionKey, server ? Smb3Cryptography.ClientToServerCipherKeyLabel : Smb3Cryptography.ServerToClientCipherKeyLabel, preauth);
    }
    internal void Sign(byte[] packet)
    {
        Wire.WriteUInt32LittleEndian(packet, Smb2Header.FlagsOffset, Wire.ReadUInt32LittleEndian(packet, Smb2Header.FlagsOffset) | Smb2HeaderFlags.Signed);
        packet.AsSpan(Smb2Header.SignatureOffset, Smb2Header.SignatureSize).Clear();
        Crypto.Cmac(signing, packet).CopyTo(packet, Smb2Header.SignatureOffset);
    }
    internal void Verify(byte[] packet)
    {
        var signature = packet[Smb2Header.SignatureOffset..Smb2Header.Size];
        var copy = (byte[])packet.Clone(); copy.AsSpan(Smb2Header.SignatureOffset, Smb2Header.SignatureSize).Clear();
        if ((Wire.ReadUInt32LittleEndian(packet, Smb2Header.FlagsOffset) & Smb2HeaderFlags.Signed) == 0 || !CryptographicOperations.FixedTimeEquals(signature, Crypto.Cmac(signing, copy))) throw new SmbException(NtStatus.AccessDenied);
    }
    internal byte[] Encrypt(byte[] packet, ulong session)
    {
        var b = new byte[Smb2TransformHeader.Size + packet.Length];
        Wire.WriteUInt32LittleEndian(b, Smb2TransformHeader.ProtocolIdOffset, Smb2TransformHeader.ProtocolId);
        int prefix = (cipher == Smb2Cipher.Aes128Gcm ? Smb3Cryptography.GcmNonceSize : Smb3Cryptography.CcmNonceSize) - Smb3Cryptography.NonceCounterSize;
        noncePrefix.AsSpan(0, prefix).CopyTo(b.AsSpan(Smb2TransformHeader.NonceOffset));
        if (nonce == ulong.MaxValue) throw new CryptographicException("Nonce exhausted.");
        Wire.WriteUInt64LittleEndian(b, Smb2TransformHeader.NonceOffset + prefix, ++nonce);
        Wire.WriteUInt32LittleEndian(b, Smb2TransformHeader.OriginalMessageSizeOffset, (uint)packet.Length);
        Wire.WriteUInt16LittleEndian(b, Smb2TransformHeader.FlagsOffset, Smb2TransformHeader.Encrypted);
        Wire.WriteUInt64LittleEndian(b, Smb2TransformHeader.SessionIdOffset, session);
        if (cipher == Smb2Cipher.Aes128Gcm)
        {
            using var aes = new AesGcm(outgoing, Smb2TransformHeader.SignatureSize);
            aes.Encrypt(b.AsSpan(Smb2TransformHeader.NonceOffset, Smb3Cryptography.GcmNonceSize), packet,
                b.AsSpan(Smb2TransformHeader.Size), b.AsSpan(Smb2TransformHeader.SignatureOffset, Smb2TransformHeader.SignatureSize),
                b.AsSpan(Smb2TransformHeader.AssociatedDataOffset, Smb2TransformHeader.AssociatedDataSize));
        }
        else
        {
            using var aes = new AesCcm(outgoing);
            aes.Encrypt(b.AsSpan(Smb2TransformHeader.NonceOffset, Smb3Cryptography.CcmNonceSize), packet,
                b.AsSpan(Smb2TransformHeader.Size), b.AsSpan(Smb2TransformHeader.SignatureOffset, Smb2TransformHeader.SignatureSize),
                b.AsSpan(Smb2TransformHeader.AssociatedDataOffset, Smb2TransformHeader.AssociatedDataSize));
        }
        return b;
    }
    internal byte[] Decrypt(byte[] packet, ulong session)
    {
        if (packet.Length < Smb2TransformHeader.Size || Wire.ReadUInt32LittleEndian(packet, Smb2TransformHeader.ProtocolIdOffset) != Smb2TransformHeader.ProtocolId ||
            Wire.ReadUInt64LittleEndian(packet, Smb2TransformHeader.SessionIdOffset) != session ||
            Wire.ReadUInt32LittleEndian(packet, Smb2TransformHeader.OriginalMessageSizeOffset) != packet.Length - Smb2TransformHeader.Size ||
            Wire.ReadUInt16LittleEndian(packet, Smb2TransformHeader.ReservedOffset) != 0 ||
            Wire.ReadUInt16LittleEndian(packet, Smb2TransformHeader.FlagsOffset) != Smb2TransformHeader.Encrypted)
            throw new SmbException(NtStatus.AccessDenied);
        var result = new byte[packet.Length - Smb2TransformHeader.Size];
        if (cipher == Smb2Cipher.Aes128Gcm)
        {
            using var aes = new AesGcm(incoming, Smb2TransformHeader.SignatureSize);
            aes.Decrypt(packet.AsSpan(Smb2TransformHeader.NonceOffset, Smb3Cryptography.GcmNonceSize), packet.AsSpan(Smb2TransformHeader.Size),
                packet.AsSpan(Smb2TransformHeader.SignatureOffset, Smb2TransformHeader.SignatureSize), result,
                packet.AsSpan(Smb2TransformHeader.AssociatedDataOffset, Smb2TransformHeader.AssociatedDataSize));
        }
        else
        {
            using var aes = new AesCcm(incoming);
            aes.Decrypt(packet.AsSpan(Smb2TransformHeader.NonceOffset, Smb3Cryptography.CcmNonceSize), packet.AsSpan(Smb2TransformHeader.Size),
                packet.AsSpan(Smb2TransformHeader.SignatureOffset, Smb2TransformHeader.SignatureSize), result,
                packet.AsSpan(Smb2TransformHeader.AssociatedDataOffset, Smb2TransformHeader.AssociatedDataSize));
        }
        return result;
    }
    public void Dispose() { CryptographicOperations.ZeroMemory(signing); CryptographicOperations.ZeroMemory(outgoing); CryptographicOperations.ZeroMemory(incoming); }
}
