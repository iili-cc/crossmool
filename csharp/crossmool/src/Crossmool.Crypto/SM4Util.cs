using System;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Security;

namespace Crossmool.Crypto
{
    public static class SM4Util
    {
        private static readonly SecureRandom Rng = new SecureRandom();

        // ECB + PKCS7Padding (compatible with Java default)
        public static byte[] encrypt(byte[] originalTextBytes, byte[] keyBytes)
        {
            if (originalTextBytes == null) throw new ArgumentNullException(nameof(originalTextBytes));
            if (keyBytes == null) throw new ArgumentNullException(nameof(keyBytes));
            if (keyBytes.Length != 16) throw new ArgumentException("SM4 key must be 16 bytes (128-bit)", nameof(keyBytes));

            var cipher = new PaddedBufferedBlockCipher(new EcbBlockCipher(new SM4Engine()));
            cipher.Init(true, new KeyParameter(keyBytes));

            var outBuf = new byte[cipher.GetOutputSize(originalTextBytes.Length)];
            int len = cipher.ProcessBytes(originalTextBytes, 0, originalTextBytes.Length, outBuf, 0);
            len += cipher.DoFinal(outBuf, len);

            var result = new byte[len];
            Buffer.BlockCopy(outBuf, 0, result, 0, len);
            return result;
        }

        public static string encrypt(string originalText, string keyString)
        {
            var input = EncodingUtils.Utf8GetBytes(originalText ?? string.Empty);
            var key = EncodingUtils.ParseBase64OrHex(keyString);
            var cipher = encrypt(input, key);
            return EncodingUtils.ToBase64(cipher);
        }

        public static string encryptToHex(string originalText, string keyString)
        {
            var input = EncodingUtils.Utf8GetBytes(originalText ?? string.Empty);
            var key = EncodingUtils.ParseBase64OrHex(keyString);
            var cipher = encrypt(input, key);
            return EncodingUtils.ToHex(cipher);
        }

        public static byte[] decrypt(byte[] encryptedTextBytes, byte[] keyBytes)
        {
            if (encryptedTextBytes == null) throw new ArgumentNullException(nameof(encryptedTextBytes));
            if (keyBytes == null) throw new ArgumentNullException(nameof(keyBytes));
            if (keyBytes.Length != 16) throw new ArgumentException("SM4 key must be 16 bytes (128-bit)", nameof(keyBytes));

            var cipher = new PaddedBufferedBlockCipher(new EcbBlockCipher(new SM4Engine()));
            cipher.Init(false, new KeyParameter(keyBytes));

            var outBuf = new byte[cipher.GetOutputSize(encryptedTextBytes.Length)];
            int len = cipher.ProcessBytes(encryptedTextBytes, 0, encryptedTextBytes.Length, outBuf, 0);
            len += cipher.DoFinal(outBuf, len);

            var result = new byte[len];
            Buffer.BlockCopy(outBuf, 0, result, 0, len);
            return result;
        }

        public static string decrypt(string encryptedText, string keyString)
        {
            var cipherBytes = EncodingUtils.ParseBase64OrHex(encryptedText);
            var key = EncodingUtils.ParseBase64OrHex(keyString);
            var plain = decrypt(cipherBytes, key);
            return EncodingUtils.Utf8GetString(plain);
        }

        public static string decryptFromHex(string encryptedTextHex, string keyString)
        {
            var cipherBytes = EncodingUtils.FromHex(encryptedTextHex);
            var key = EncodingUtils.ParseBase64OrHex(keyString);
            var plain = decrypt(cipherBytes, key);
            return EncodingUtils.Utf8GetString(plain);
        }
    }
}
