using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Tedd.Smb;

internal static class Crypto
{
    // These tables have static backing storage instead of allocating in each round.
    private static ReadOnlySpan<byte> Md4RoundThreeOrder => [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    private static ReadOnlySpan<byte> Md4Rotations => [3, 7, 11, 19, 3, 5, 9, 13, 3, 9, 11, 15];

    // RFC 1320. MD4 is used only for the NT password hash required by NTLMv2.
    internal static byte[] Md4(byte[] input)
    {
        var b = new byte[((input.Length + 9 + 63) / 64) * 64];
        input.CopyTo(b, 0);
        b[input.Length] = 0x80;
        BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(b.Length - 8), (ulong)input.Length * 8);
        uint a = 0x67452301, c = 0x98badcfe, d = 0x10325476, v = 0xefcdab89;
        Span<uint> x = stackalloc uint[16];
        for (int offset = 0; offset < b.Length; offset += 64)
        {
            for (int i = 0; i < 16; i++)
                x[i] = Wire.ReadUInt32LittleEndian(b, offset + i * 4);
            uint aa = a, bb = v, cc = c, dd = d;
            for (int round = 0; round < 3; round++)
                for (int i = 0; i < 16; i++)
                {
                    int k = round switch
                    {
                        0 => i,
                        1 => (i % 4) * 4 + i / 4,
                        _ => Md4RoundThreeOrder[i]
                    };
                    int s = Md4Rotations[round * 4 + i % 4];
                    uint f = round switch
                    {
                        0 => (v & c) | (~v & d),
                        1 => (v & c) | (v & d) | (c & d),
                        _ => v ^ c ^ d
                    };
                    uint z = BitOperations.RotateLeft(unchecked(a + f + x[k] + (round switch
                    {
                        1 => 0x5a827999u,
                        2 => 0x6ed9eba1u,
                        _ => 0u
                    })), s);
                    a = d;
                    d = c;
                    c = v;
                    v = z;
                }

            a = unchecked(a + aa);
            v = unchecked(v + bb);
            c = unchecked(c + cc);
            d = unchecked(d + dd);
        }

        var result = new byte[16];
        Wire.WriteUInt32LittleEndian(result, 0, a);
        Wire.WriteUInt32LittleEndian(result, 4, v);
        Wire.WriteUInt32LittleEndian(result, 8, c);
        Wire.WriteUInt32LittleEndian(result, 12, d);
        CryptographicOperations.ZeroMemory(b);
        x.Clear();
        return result;
    }

    internal static byte[] Rc4(byte[] key, byte[] data)
    {
        // RC4 is restricted to NTLM key exchange, never SMB payload encryption.
        Span<byte> s = stackalloc byte[256];
        for (int i = 0; i < s.Length; i++)
            s[i] = (byte)i;
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 255;
            (s[i], s[j]) = (s[j], s[i]);
        }

        var result = new byte[data.Length];
        int a = 0;
        j = 0;
        for (int k = 0; k < data.Length; k++)
        {
            a = (a + 1) & 255;
            j = (j + s[a]) & 255;
            (s[a], s[j]) = (s[j], s[a]);
            result[k] = (byte)(data[k] ^ s[(s[a] + s[j]) & 255]);
        }

        CryptographicOperations.ZeroMemory(s);
        return result;
    }

    internal static byte[] Kdf(byte[] key, string label, byte[] context)
    {
        // SP800-108 counter mode, label includes its protocol-specified NUL.
        var b = Wire.Join(new byte[] { 0, 0, 0, 1 }, Encoding.ASCII.GetBytes(label + "\0"), new byte[1], context, new byte[] { 0, 0, 0, 128 });
        return HMACSHA256.HashData(key, b)[..16];
    }

    internal static byte[] Cmac(byte[] key, byte[] message)
    {
        using var cmac = new AesCmac(key);
        var result = new byte[Smb3Header.SignatureSize];
        cmac.Compute(message, result);
        return result;
    }
}

/// <summary>RFC 4493 CMAC with a reusable key schedule and fixed session scratch buffers.</summary>
/// <remarks>Instances require serialized access, as provided by each SMB connection.</remarks>
internal sealed class AesCmac : IDisposable
{
    private const int BlockSize = 16;
    private readonly ICryptoTransform encryptor;
    private readonly byte[] fullBlockKey = new byte[BlockSize];
    private readonly byte[] paddedBlockKey = new byte[BlockSize];
    private readonly byte[] block = new byte[BlockSize];
    private readonly byte[] state = new byte[BlockSize];
    internal AesCmac(byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        encryptor = aes.CreateEncryptor();
        encryptor.TransformBlock(block, 0, BlockSize, state, 0);
        Double(state, fullBlockKey);
        Double(fullBlockKey, paddedBlockKey);
        CryptographicOperations.ZeroMemory(state);
    }

    // Doubling in GF(2^128) uses the reduction polynomial specified by RFC 4493.
    private static void Double(ReadOnlySpan<byte> input, Span<byte> output)
    {
        int carry = 0;
        for (int i = BlockSize - 1; i >= 0; i--)
        {
            output[i] = (byte)((input[i] << 1) | carry);
            carry = input[i] >> 7;
        }

        if (carry != 0)
            output[^1] ^= 0x87;
    }

    internal void Compute(ReadOnlySpan<byte> message, Span<byte> destination, bool smbSignature = false)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, BlockSize);
        state.AsSpan().Clear();
        int blocks = Math.Max(1, (message.Length + BlockSize - 1) / BlockSize);
        try
        {
            for (int i = 0; i < blocks; i++)
            {
                int offset = i * BlockSize;
                int count = Math.Min(BlockSize, message.Length - offset);
                block.AsSpan().Clear();
                message.Slice(offset, count).CopyTo(block);
                // Mask the aligned signature block without cloning or modifying the packet.
                if (smbSignature && offset == Smb3Header.SignatureOffset)
                    block.AsSpan().Clear();
                if (i == blocks - 1)
                {
                    ReadOnlySpan<byte> subkey = count == BlockSize ? fullBlockKey : paddedBlockKey;
                    if (count < BlockSize)
                        block[count] = 0x80;
                    for (int k = 0; k < BlockSize; k++)
                        block[k] ^= subkey[k];
                }

                for (int k = 0; k < BlockSize; k++)
                    block[k] ^= state[k];
                encryptor.TransformBlock(block, 0, BlockSize, state, 0);
            }

            state.AsSpan().CopyTo(destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
            CryptographicOperations.ZeroMemory(state);
        }
    }

    public void Dispose()
    {
        encryptor.Dispose();
        CryptographicOperations.ZeroMemory(fullBlockKey);
        CryptographicOperations.ZeroMemory(paddedBlockKey);
        CryptographicOperations.ZeroMemory(block);
        CryptographicOperations.ZeroMemory(state);
    }
}

/// <summary>Owns session keys, reusable signing state, and the outgoing nonce counter.</summary>
/// <remarks>Connection serialization protects signing state and nonce uniqueness.</remarks>
internal sealed class SessionCrypto : IDisposable
{
    private readonly AesCmac signing;
    private readonly byte[] outgoing;
    private readonly byte[] incoming;
    private readonly byte[] noncePrefix = RandomNumberGenerator.GetBytes(Smb3Cryptography.GcmNonceSize - Smb3Cryptography.NonceCounterSize);
    private ulong nonce;
    private readonly int cipher;
    internal SessionCrypto(byte[] sessionKey, byte[] preauth, bool server, int cipher = Smb3Cipher.Aes128Gcm)
    {
        this.cipher = cipher;
        outgoing = Crypto.Kdf(sessionKey, server ? Smb3Cryptography.ServerToClientCipherKeyLabel : Smb3Cryptography.ClientToServerCipherKeyLabel, preauth);
        incoming = Crypto.Kdf(sessionKey, server ? Smb3Cryptography.ClientToServerCipherKeyLabel : Smb3Cryptography.ServerToClientCipherKeyLabel, preauth);
        byte[] signingKey = Crypto.Kdf(sessionKey, Smb3Cryptography.SigningKeyLabel, preauth);
        try
        {
            signing = new AesCmac(signingKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(outgoing);
            CryptographicOperations.ZeroMemory(incoming);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingKey);
        }
    }

    internal void Sign(byte[] packet)
    {
        Wire.WriteUInt32LittleEndian(packet, Smb3Header.FlagsOffset, Wire.ReadUInt32LittleEndian(packet, Smb3Header.FlagsOffset) | Smb3HeaderFlags.Signed);
        signing.Compute(packet, packet.AsSpan(Smb3Header.SignatureOffset, Smb3Header.SignatureSize), smbSignature: true);
    }

    internal void Verify(ReadOnlySpan<byte> packet)
    {
        Wire.Validate(packet);
        if ((Wire.ReadUInt32LittleEndian(packet, Smb3Header.FlagsOffset) & Smb3HeaderFlags.Signed) == 0)
            throw new SmbException(NtStatus.AccessDenied);
        Span<byte> expected = stackalloc byte[Smb3Header.SignatureSize];
        signing.Compute(packet, expected, smbSignature: true);
        bool valid = CryptographicOperations.FixedTimeEquals(packet.Slice(Smb3Header.SignatureOffset, Smb3Header.SignatureSize), expected);
        CryptographicOperations.ZeroMemory(expected);
        if (!valid)
            throw new SmbException(NtStatus.AccessDenied);
    }

    internal byte[] Encrypt(byte[] packet, ulong session)
    {
        var b = new byte[Smb3TransformHeader.Size + packet.Length];
        Wire.WriteUInt32LittleEndian(b, Smb3TransformHeader.ProtocolIdOffset, Smb3TransformHeader.ProtocolId);
        int prefix = (cipher == Smb3Cipher.Aes128Gcm ? Smb3Cryptography.GcmNonceSize : Smb3Cryptography.CcmNonceSize) - Smb3Cryptography.NonceCounterSize;
        noncePrefix.AsSpan(0, prefix).CopyTo(b.AsSpan(Smb3TransformHeader.NonceOffset));
        if (nonce == ulong.MaxValue)
            throw new CryptographicException("Nonce exhausted.");
        Wire.WriteUInt64LittleEndian(b, Smb3TransformHeader.NonceOffset + prefix, ++nonce);
        Wire.WriteUInt32LittleEndian(b, Smb3TransformHeader.OriginalMessageSizeOffset, (uint)packet.Length);
        Wire.WriteUInt16LittleEndian(b, Smb3TransformHeader.FlagsOffset, Smb3TransformHeader.Encrypted);
        Wire.WriteUInt64LittleEndian(b, Smb3TransformHeader.SessionIdOffset, session);
        if (cipher == Smb3Cipher.Aes128Gcm)
        {
            using var aes = new AesGcm(outgoing, Smb3TransformHeader.SignatureSize);
            aes.Encrypt(b.AsSpan(Smb3TransformHeader.NonceOffset, Smb3Cryptography.GcmNonceSize), packet, b.AsSpan(Smb3TransformHeader.Size), b.AsSpan(Smb3TransformHeader.SignatureOffset, Smb3TransformHeader.SignatureSize), b.AsSpan(Smb3TransformHeader.AssociatedDataOffset, Smb3TransformHeader.AssociatedDataSize));
        }
        else
        {
            using var aes = new AesCcm(outgoing);
            aes.Encrypt(b.AsSpan(Smb3TransformHeader.NonceOffset, Smb3Cryptography.CcmNonceSize), packet, b.AsSpan(Smb3TransformHeader.Size), b.AsSpan(Smb3TransformHeader.SignatureOffset, Smb3TransformHeader.SignatureSize), b.AsSpan(Smb3TransformHeader.AssociatedDataOffset, Smb3TransformHeader.AssociatedDataSize));
        }

        return b;
    }

    internal byte[] Decrypt(byte[] packet, ulong session)
    {
        if (packet.Length < Smb3TransformHeader.Size || Wire.ReadUInt32LittleEndian(packet, Smb3TransformHeader.ProtocolIdOffset) != Smb3TransformHeader.ProtocolId || Wire.ReadUInt64LittleEndian(packet, Smb3TransformHeader.SessionIdOffset) != session || Wire.ReadUInt32LittleEndian(packet, Smb3TransformHeader.OriginalMessageSizeOffset) != packet.Length - Smb3TransformHeader.Size || Wire.ReadUInt16LittleEndian(packet, Smb3TransformHeader.ReservedOffset) != 0 || Wire.ReadUInt16LittleEndian(packet, Smb3TransformHeader.FlagsOffset) != Smb3TransformHeader.Encrypted)
            throw new SmbException(NtStatus.AccessDenied);
        var result = new byte[packet.Length - Smb3TransformHeader.Size];
        if (cipher == Smb3Cipher.Aes128Gcm)
        {
            using var aes = new AesGcm(incoming, Smb3TransformHeader.SignatureSize);
            aes.Decrypt(packet.AsSpan(Smb3TransformHeader.NonceOffset, Smb3Cryptography.GcmNonceSize), packet.AsSpan(Smb3TransformHeader.Size), packet.AsSpan(Smb3TransformHeader.SignatureOffset, Smb3TransformHeader.SignatureSize), result, packet.AsSpan(Smb3TransformHeader.AssociatedDataOffset, Smb3TransformHeader.AssociatedDataSize));
        }
        else
        {
            using var aes = new AesCcm(incoming);
            aes.Decrypt(packet.AsSpan(Smb3TransformHeader.NonceOffset, Smb3Cryptography.CcmNonceSize), packet.AsSpan(Smb3TransformHeader.Size), packet.AsSpan(Smb3TransformHeader.SignatureOffset, Smb3TransformHeader.SignatureSize), result, packet.AsSpan(Smb3TransformHeader.AssociatedDataOffset, Smb3TransformHeader.AssociatedDataSize));
        }

        return result;
    }

    public void Dispose()
    {
        signing.Dispose();
        CryptographicOperations.ZeroMemory(outgoing);
        CryptographicOperations.ZeroMemory(incoming);
        CryptographicOperations.ZeroMemory(noncePrefix);
    }
}
