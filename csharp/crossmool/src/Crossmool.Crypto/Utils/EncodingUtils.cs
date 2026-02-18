using System;
using System.Text;

namespace Crossmool.Crypto.Utils
{
    public static class EncodingUtils
    {
        public static readonly Encoding Utf8 = new UTF8Encoding(false);

        public static byte[] Utf8GetBytes(string s)
        {
            return s == null ? Array.Empty<byte>() : Utf8.GetBytes(s);
        }

        public static string Utf8GetString(byte[] bytes)
        {
            return bytes == null ? string.Empty : Utf8.GetString(bytes);
        }

        public static string ToBase64(byte[] bytes)
        {
            return bytes == null ? string.Empty : Convert.ToBase64String(bytes);
        }

        public static byte[] FromBase64(string base64)
        {
            return string.IsNullOrWhiteSpace(base64) ? Array.Empty<byte>() : Convert.FromBase64String(base64);
        }

        public static string ToHex(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0) return string.Empty;
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
                sb.AppendFormat("{0:x2}", b);
            return sb.ToString();
        }

        public static byte[] FromHex(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex)) return Array.Empty<byte>();
            hex = hex.Trim();
            if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex.Substring(2);
            if (hex.Length % 2 != 0) throw new FormatException("Hex string must have even length");
            var result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return result;
        }

        public static bool LooksLikeHex(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return false;
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
            if (s.Length % 2 != 0) return false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                bool isHexChar = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!isHexChar) return false;
            }
            return true;
        }

        public static byte[] ParseBase64OrHex(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return Array.Empty<byte>();
            s = s.Trim();
            if (LooksLikeHex(s))
            {
                return FromHex(s);
            }
            try
            {
                return FromBase64(s);
            }
            catch (FormatException)
            {
                // Fallback to hex if Base64 fails
                return FromHex(s);
            }
        }
    }
}
