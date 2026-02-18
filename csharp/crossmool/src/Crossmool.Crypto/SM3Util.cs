using System;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Crypto.Digests;

namespace Crossmool.Crypto
{
    public static class SM3Util
    {
        public static byte[] digest(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            var d = new SM3Digest();
            d.BlockUpdate(input, 0, input.Length);
            var output = new byte[d.GetDigestSize()];
            d.DoFinal(output, 0);
            return output;
        }

        public static string digest(string input)
        {
            var bytes = EncodingUtils.Utf8GetBytes(input ?? string.Empty);
            var hash = digest(bytes);
            return EncodingUtils.ToHex(hash);
        }

        public static string digestBase64(string input)
        {
            var bytes = EncodingUtils.Utf8GetBytes(input ?? string.Empty);
            var hash = digest(bytes);
            return EncodingUtils.ToBase64(hash);
        }
    }
}
