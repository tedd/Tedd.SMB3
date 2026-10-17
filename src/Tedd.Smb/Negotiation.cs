using System.Security.Cryptography;

namespace Tedd.Smb;

internal static class Negotiation
{
    internal static byte[] Context(int type, byte[] data)
    {
        var b = new byte[Wire.Align(8 + data.Length)]; Wire.W16(b, 0, type); Wire.W16(b, 2, data.Length); data.CopyTo(b, 8); return b;
    }
    internal static byte[] Contexts(bool signing = true, int cipher = 2, bool offerBoth = false)
    {
        var preauth = new byte[38]; Wire.W16(preauth, 0, 1); Wire.W16(preauth, 2, 32); Wire.W16(preauth, 4, 1); RandomNumberGenerator.Fill(preauth.AsSpan(6));
        return Wire.Join(Context(1, preauth), Context(2, offerBoth ? new byte[] { 2, 0, 2, 0, 1, 0 } : new byte[] { 1, 0, (byte)cipher, 0 }), signing ? Context(8, new byte[] { 1, 0, 1, 0 }) : []);
    }
    internal static (bool Signing, int Cipher) ValidateContexts(byte[] packet, int offset, int count, bool response)
    {
        if (count is < 1 or > 32 || offset < 100 || (offset & 7) != 0) throw new SmbException(Status.InvalidParameter);
        bool hash = false, signing = false; int cipher = 0; var seen = new HashSet<ushort>();
        for (int i = 0; i < count; i++)
        {
            var h = Wire.Slice(packet, offset, 8); ushort type = Wire.U16(h, 0); int n = Wire.U16(h, 2); var data = Wire.Slice(packet, offset + 8, n);
            if (!seen.Add(type)) throw new SmbException(Status.InvalidParameter);
            if (type is 1 or 2 or 8)
            {
                int number = Wire.U16(data, 0), start = type == 1 ? 4 : 2;
                if (number < 1 || (response && number != 1)) throw new SmbException(Status.NotSupported);
                var values = Wire.Slice(data, start, checked(number * 2)); bool match = false;
                for (int j = 0; j < number; j++)
                {
                    int algorithm = Wire.U16(values, j * 2);
                    if (type == 2 && algorithm is 1 or 2) { cipher = Math.Max(cipher, algorithm); match = true; }
                    else if (type != 2 && algorithm == 1) match = true;
                }
                if (!match) throw new SmbException(Status.NotSupported);
                if (type == 1) { _ = Wire.Slice(data, start + number * 2, Wire.U16(data, 2)); hash = true; }
                if (type == 8) signing = true;
            }
            offset = checked(offset + Wire.Align(8 + n));
        }
        if (!hash || cipher == 0) throw new SmbException(Status.NotSupported);
        return (signing, cipher);
    }
    internal static byte[] Hash(byte[] previous, byte[] packet) => SHA512.HashData(Wire.Join(previous, packet));
}
