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

        // CBC + PKCS7Padding, IV prefixed to ciphertext
        public static byte[] encrypt(byte[] originalTextBytes, byte[] keyBytes)
        {
            if (originalTextBytes == null) throw new ArgumentNullException(nameof(originalTextBytes));
            if (keyBytes == null) throw new ArgumentNullException(nameof(keyBytes));
            if (keyBytes.Length != 16) throw new ArgumentException("SM4 key must be 16 bytes (128-bit)", nameof(keyBytes));

            var iv = new byte[16];
            Rng.NextBytes(iv);
            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SM4Engine()));
            cipher.Init(true, new ParametersWithIV(new KeyParameter(keyBytes), iv));

            var input = originalTextBytes;
            var outBuf = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, outBuf, 0);
            len += cipher.DoFinal(outBuf, len);

            var result = new byte[iv.Length + len];
            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(outBuf, 0, result, iv.Length, len);
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
            if (encryptedTextBytes.Length < 16) throw new ArgumentException("Ciphertext must include 16-byte IV prefix", nameof(encryptedTextBytes));

            var iv = new byte[16];
            Buffer.BlockCopy(encryptedTextBytes, 0, iv, 0, 16);
            var payload = new byte[encryptedTextBytes.Length - 16];
            Buffer.BlockCopy(encryptedTextBytes, 16, payload, 0, payload.Length);

            var cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new SM4Engine()));
            cipher.Init(false, new ParametersWithIV(new KeyParameter(keyBytes), iv));

            var outBuf = new byte[cipher.GetOutputSize(payload.Length)];
            int len = cipher.ProcessBytes(payload, 0, payload.Length, outBuf, 0);
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
