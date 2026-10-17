using System.Security.Cryptography;

namespace Tedd.Smb;

internal static class Negotiation
{
    internal const int BaseContextCount = 2, ContextCountWithSigning = BaseContextCount + 1;
    internal static byte[] Context(int type, byte[] data)
    {
        var b = new byte[Wire.Align(Smb2NegotiateContext.HeaderSize + data.Length)];
        Wire.WriteUInt16LittleEndian(b, Smb2NegotiateContext.ContextTypeOffset, type);
        Wire.WriteUInt16LittleEndian(b, Smb2NegotiateContext.DataLengthOffset, data.Length);
        data.CopyTo(b, Smb2NegotiateContext.HeaderSize);
        return b;
    }
    internal static byte[] Contexts(bool signing = true, int cipher = Smb2Cipher.Aes128Gcm, bool offerBoth = false)
    {
        int saltOffset = Smb2PreauthIntegrityCapabilities.HashAlgorithmsOffset + sizeof(ushort);
        var preauth = new byte[saltOffset + SmbLimits.PreauthSaltSize];
        Wire.WriteUInt16LittleEndian(preauth, Smb2PreauthIntegrityCapabilities.HashAlgorithmCountOffset, 1);
        Wire.WriteUInt16LittleEndian(preauth, Smb2PreauthIntegrityCapabilities.SaltLengthOffset, SmbLimits.PreauthSaltSize);
        Wire.WriteUInt16LittleEndian(preauth, Smb2PreauthIntegrityCapabilities.HashAlgorithmsOffset, Smb2PreauthHashAlgorithm.Sha512);
        RandomNumberGenerator.Fill(preauth.AsSpan(saltOffset));
        var encryption = Algorithms(offerBoth ? [Smb2Cipher.Aes128Gcm, Smb2Cipher.Aes128Ccm] : [checked((ushort)cipher)]);
        return Wire.Join(
            Context(Smb2NegotiateContextType.PreauthIntegrityCapabilities, preauth),
            Context(Smb2NegotiateContextType.EncryptionCapabilities, encryption),
            signing ? Context(Smb2NegotiateContextType.SigningCapabilities, Algorithms([Smb2SigningAlgorithm.AesCmac])) : []);
    }
    private static byte[] Algorithms(ushort[] algorithms)
    {
        var data = new byte[Smb2AlgorithmCapabilities.AlgorithmsOffset + algorithms.Length * sizeof(ushort)];
        Wire.WriteUInt16LittleEndian(data, Smb2AlgorithmCapabilities.AlgorithmCountOffset, algorithms.Length);
        for (int i = 0; i < algorithms.Length; i++)
            Wire.WriteUInt16LittleEndian(data, Smb2AlgorithmCapabilities.AlgorithmsOffset + i * sizeof(ushort), algorithms[i]);
        return data;
    }
    internal static (bool Signing, int Cipher) ValidateContexts(byte[] packet, int offset, int count, bool response)
    {
        if (count is < 1 or > SmbLimits.MaxNegotiateContexts || offset < Smb2Header.Size + Smb2NegotiateRequest.FixedSize || (offset & 7) != 0) throw new SmbException(NtStatus.InvalidParameter);
        bool hash = false, signing = false; int cipher = Smb2Cipher.None; var seen = new HashSet<ushort>();
        for (int i = 0; i < count; i++)
        {
            var h = Wire.Slice(packet, offset, Smb2NegotiateContext.HeaderSize);
            ushort type = Wire.ReadUInt16LittleEndian(h, Smb2NegotiateContext.ContextTypeOffset);
            int n = Wire.ReadUInt16LittleEndian(h, Smb2NegotiateContext.DataLengthOffset);
            var data = Wire.Slice(packet, offset + Smb2NegotiateContext.HeaderSize, n);
            if (!seen.Add(type)) throw new SmbException(NtStatus.InvalidParameter);
            if (type is Smb2NegotiateContextType.PreauthIntegrityCapabilities or Smb2NegotiateContextType.EncryptionCapabilities or Smb2NegotiateContextType.SigningCapabilities)
            {
                int number = Wire.ReadUInt16LittleEndian(data, Smb2AlgorithmCapabilities.AlgorithmCountOffset);
                int start = type == Smb2NegotiateContextType.PreauthIntegrityCapabilities
                    ? Smb2PreauthIntegrityCapabilities.HashAlgorithmsOffset : Smb2AlgorithmCapabilities.AlgorithmsOffset;
                if (number < 1 || (response && number != 1)) throw new SmbException(NtStatus.NotSupported);
                var values = Wire.Slice(data, start, checked(number * sizeof(ushort))); bool match = false;
                for (int j = 0; j < number; j++)
                {
                    int algorithm = Wire.ReadUInt16LittleEndian(values, j * sizeof(ushort));
                    if (type == Smb2NegotiateContextType.EncryptionCapabilities && algorithm is Smb2Cipher.Aes128Ccm or Smb2Cipher.Aes128Gcm) { cipher = Math.Max(cipher, algorithm); match = true; }
                    else if (type == Smb2NegotiateContextType.PreauthIntegrityCapabilities && algorithm == Smb2PreauthHashAlgorithm.Sha512) match = true;
                    else if (type == Smb2NegotiateContextType.SigningCapabilities && algorithm == Smb2SigningAlgorithm.AesCmac) match = true;
                }
                if (!match) throw new SmbException(NtStatus.NotSupported);
                if (type == Smb2NegotiateContextType.PreauthIntegrityCapabilities) { _ = Wire.Slice(data, start + number * sizeof(ushort), Wire.ReadUInt16LittleEndian(data, Smb2PreauthIntegrityCapabilities.SaltLengthOffset)); hash = true; }
                if (type == Smb2NegotiateContextType.SigningCapabilities) signing = true;
            }
            offset = checked(offset + Wire.Align(Smb2NegotiateContext.HeaderSize + n));
        }
        if (!hash || cipher == Smb2Cipher.None) throw new SmbException(NtStatus.NotSupported);
        return (signing, cipher);
    }
    internal static byte[] Hash(byte[] previous, byte[] packet) => SHA512.HashData(Wire.Join(previous, packet));
}
