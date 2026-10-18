using System.Security.Cryptography;

namespace Tedd.SMB3;

/// <summary>SMB 3.1.1 algorithm negotiation and preauthentication transcript hashing.</summary>
internal static class Negotiation
{
    internal const int BaseContextCount = 2;
    internal const int ContextCountWithSigning = BaseContextCount + 1;
    internal static byte[] Context(int type, byte[] data)
    {
        var b = new byte[Wire.Align(Smb3NegotiateContext.HeaderSize + data.Length)];
        Wire.WriteUInt16LittleEndian(b, Smb3NegotiateContext.ContextTypeOffset, type);
        Wire.WriteUInt16LittleEndian(b, Smb3NegotiateContext.DataLengthOffset, data.Length);
        data.CopyTo(b, Smb3NegotiateContext.HeaderSize);
        return b;
    }

    internal static byte[] Contexts(bool signing = true, int cipher = Smb3Cipher.Aes128Gcm, bool offerBoth = false)
    {
        int saltOffset = Smb3PreauthIntegrityCapabilities.HashAlgorithmsOffset + sizeof(ushort);
        var preauth = new byte[saltOffset + SmbLimits.PreauthSaltSize];
        Wire.WriteUInt16LittleEndian(preauth, Smb3PreauthIntegrityCapabilities.HashAlgorithmCountOffset, 1);
        Wire.WriteUInt16LittleEndian(preauth, Smb3PreauthIntegrityCapabilities.SaltLengthOffset, SmbLimits.PreauthSaltSize);
        Wire.WriteUInt16LittleEndian(preauth, Smb3PreauthIntegrityCapabilities.HashAlgorithmsOffset, Smb3PreauthHashAlgorithm.Sha512);
        RandomNumberGenerator.Fill(preauth.AsSpan(saltOffset));
        var encryption = Algorithms(offerBoth ? [Smb3Cipher.Aes128Gcm, Smb3Cipher.Aes128Ccm] : [checked((ushort)cipher)]);
        return Wire.Join(Context(Smb3NegotiateContextType.PreauthIntegrityCapabilities, preauth), Context(Smb3NegotiateContextType.EncryptionCapabilities, encryption), signing ? Context(Smb3NegotiateContextType.SigningCapabilities, Algorithms([Smb3SigningAlgorithm.AesCmac])) : []);
    }

    private static byte[] Algorithms(ushort[] algorithms)
    {
        var data = new byte[Smb3AlgorithmCapabilities.AlgorithmsOffset + algorithms.Length * sizeof(ushort)];
        Wire.WriteUInt16LittleEndian(data, Smb3AlgorithmCapabilities.AlgorithmCountOffset, algorithms.Length);
        for (int i = 0; i < algorithms.Length; i++)
            Wire.WriteUInt16LittleEndian(data, Smb3AlgorithmCapabilities.AlgorithmsOffset + i * sizeof(ushort), algorithms[i]);
        return data;
    }

    internal static (bool Signing, int Cipher) ValidateContexts(ReadOnlySpan<byte> packet, int offset, int count, bool response)
    {
        if (count is < 1 or > SmbLimits.MaxNegotiateContexts || offset < Smb3Header.Size + Smb3NegotiateRequest.FixedSize || (offset & 7) != 0)
            throw new SmbException(NtStatus.InvalidParameter);
        bool hash = false, signing = false;
        int cipher = Smb3Cipher.None;
        var seen = new HashSet<ushort>();
        for (int i = 0; i < count; i++)
        {
            var h = Wire.Slice(packet, offset, Smb3NegotiateContext.HeaderSize);
            ushort type = Wire.ReadUInt16LittleEndian(h, Smb3NegotiateContext.ContextTypeOffset);
            int n = Wire.ReadUInt16LittleEndian(h, Smb3NegotiateContext.DataLengthOffset);
            var data = Wire.Slice(packet, offset + Smb3NegotiateContext.HeaderSize, n);
            if (!seen.Add(type))
                throw new SmbException(NtStatus.InvalidParameter);
            if (type is Smb3NegotiateContextType.PreauthIntegrityCapabilities or Smb3NegotiateContextType.EncryptionCapabilities or Smb3NegotiateContextType.SigningCapabilities)
            {
                int number = Wire.ReadUInt16LittleEndian(data, Smb3AlgorithmCapabilities.AlgorithmCountOffset);
                int start = type == Smb3NegotiateContextType.PreauthIntegrityCapabilities ? Smb3PreauthIntegrityCapabilities.HashAlgorithmsOffset : Smb3AlgorithmCapabilities.AlgorithmsOffset;
                if (number < 1 || (response && number != 1))
                    throw new SmbException(NtStatus.NotSupported);
                var values = Wire.Slice(data, start, checked(number * sizeof(ushort)));
                bool match = false;
                for (int j = 0; j < number; j++)
                {
                    int algorithm = Wire.ReadUInt16LittleEndian(values, j * sizeof(ushort));
                    if (type == Smb3NegotiateContextType.EncryptionCapabilities && algorithm is Smb3Cipher.Aes128Ccm or Smb3Cipher.Aes128Gcm)
                    {
                        cipher = Math.Max(cipher, algorithm);
                        match = true;
                    }
                    else if (type == Smb3NegotiateContextType.PreauthIntegrityCapabilities && algorithm == Smb3PreauthHashAlgorithm.Sha512)
                        match = true;
                    else if (type == Smb3NegotiateContextType.SigningCapabilities && algorithm == Smb3SigningAlgorithm.AesCmac)
                        match = true;
                }

                if (!match)
                    throw new SmbException(NtStatus.NotSupported);
                if (type == Smb3NegotiateContextType.PreauthIntegrityCapabilities)
                {
                    _ = Wire.Slice(data, start + number * sizeof(ushort), Wire.ReadUInt16LittleEndian(data, Smb3PreauthIntegrityCapabilities.SaltLengthOffset));
                    hash = true;
                }

                if (type == Smb3NegotiateContextType.SigningCapabilities)
                    signing = true;
            }

            offset = checked(offset + Wire.Align(Smb3NegotiateContext.HeaderSize + n));
        }

        if (!hash || cipher == Smb3Cipher.None)
            throw new SmbException(NtStatus.NotSupported);
        return (signing, cipher);
    }

    internal static byte[] Hash(ReadOnlySpan<byte> previous, ReadOnlySpan<byte> packet)
    {
        // Append avoids allocating a concatenation of the entire transcript step.
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA512);
        hash.AppendData(previous);
        hash.AppendData(packet);
        return hash.GetHashAndReset();
    }
}
