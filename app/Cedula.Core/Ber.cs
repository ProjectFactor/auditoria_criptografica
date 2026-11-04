namespace Cedula.Core;
public record Tlv(string Tag, int Offset, int Header, byte[] Value)
{
    public int Length => Header + Value.Length;
}
public static class Ber
{
    public static List<Tlv> Read(byte[] bytes, int baseOffset = 0)
    {
        var result = new List<Tlv>(); int p = 0;
        while (p < bytes.Length)
        {
            int start = p; byte first = bytes[p++];
            if (first == 0 && bytes.AsSpan(start).IndexOfAnyExcept((byte)0) < 0) break;
            if ((first & 31) == 31)
            {
                int count = 0;
                do { if (p >= bytes.Length || ++count > 4) throw new InvalidDataException("Invalid BER tag"); } while ((bytes[p++] & 128) != 0);
            }
            string tag = Convert.ToHexString(bytes.AsSpan(start, p - start));
            if (p >= bytes.Length) throw new InvalidDataException("Missing BER length");
            int n = bytes[p++];
            if ((n & 128) != 0)
            {
                int count = n & 127; n = 0;
                if (count is 0 or > 4 || p + count > bytes.Length) throw new InvalidDataException("Unsupported BER length");
                for (int i = 0; i < count; i++) n = checked(n * 256 + bytes[p++]);
            }
            if (n < 0 || n > bytes.Length - p) throw new InvalidDataException("Truncated BER value");
            result.Add(new(tag, baseOffset + start, p - start, bytes.AsSpan(p, n).ToArray())); p += n;
        }
        return result;
    }
    public static IEnumerable<Tlv> Walk(byte[] bytes, int offset = 0, int depth = 0)
    {
        if (depth > 24) throw new InvalidDataException("BER nesting limit");
        foreach (var t in Read(bytes, offset))
        {
            yield return t;
            if ((Convert.ToByte(t.Tag[..2], 16) & 32) != 0)
                foreach (var child in Walk(t.Value, t.Offset + t.Header, depth + 1)) yield return child;
        }
    }
    public static byte[] Join(params byte[][] parts) => parts.SelectMany(x => x).ToArray();
    public static byte[] Encode(string tag, byte[] bytes)
    {
        byte[] len = bytes.Length < 128 ? [(byte)bytes.Length] : bytes.Length < 256 ? [0x81, (byte)bytes.Length] : [0x82, (byte)(bytes.Length >> 8), (byte)bytes.Length];
        return Join(Format.Bytes(tag), len, bytes);
    }
}
