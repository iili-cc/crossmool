using System;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Security;

namespace Crossmool.Crypto
{
    public static class SM4Util
    {
        private static readonly SecureRandom Rng = new SecureRandom();
        private const int GcmIvSize = 12;   // 96 bits
        private const int GcmTagSize = 16;   // 128 bits
        private const int GcmTagSizeBits = 128;

        public static byte[] GenerateKey()
        {
            var key = new byte[16];
            Rng.NextBytes(key);
            return key;
        }

        public static string GenerateKeyAsHex()
        {
            return EncodingUtils.ToHex(GenerateKey());
        }

        public static byte[] ParseHexKey(string hexKey)
        {
            return EncodingUtils.FromHex(hexKey);
        }

        /// <summary>
        /// SM4 GCM 加密，返回 Base64(IV[12] + 密文 + Tag[16])
        /// </summary>
        public static string EncryptGcm(byte[] key, byte[] plaintext)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 16) throw new ArgumentException("SM4 key must be 16 bytes (128-bit)", nameof(key));
            if (plaintext == null) throw new ArgumentNullException(nameof(plaintext));

            var iv = new byte[GcmIvSize];
            Rng.NextBytes(iv);

            var cipher = new GcmBlockCipher(new SM4Engine());
            var parameters = new AeadParameters(new KeyParameter(key), GcmTagSizeBits, iv);
            cipher.Init(true, parameters);

            var output = new byte[cipher.GetOutputSize(plaintext.Length)];
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
            len += cipher.DoFinal(output, len);

            var cipherText = new byte[len];
            Buffer.BlockCopy(output, 0, cipherText, 0, len);

            // 组合: IV(12) + 密文(含Tag)
            var combined = new byte[iv.Length + cipherText.Length];
            Buffer.BlockCopy(iv, 0, combined, 0, iv.Length);
            Buffer.BlockCopy(cipherText, 0, combined, iv.Length, cipherText.Length);

            return EncodingUtils.ToBase64(combined);
        }

        /// <summary>
        /// SM4 GCM 解密，输入 Base64(IV[12] + 密文 + Tag[16])
        /// </summary>
        public static byte[] DecryptGcm(byte[] key, string ciphertextBase64)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 16) throw new ArgumentException("SM4 key must be 16 bytes (128-bit)", nameof(key));
            if (string.IsNullOrEmpty(ciphertextBase64)) throw new ArgumentNullException(nameof(ciphertextBase64));

            var data = EncodingUtils.FromBase64(ciphertextBase64);
            if (data.Length < GcmIvSize + GcmTagSize)
                throw new ArgumentException("Invalid GCM ciphertext: too short");

            var iv = new byte[GcmIvSize];
            var cipherText = new byte[data.Length - GcmIvSize];
            Buffer.BlockCopy(data, 0, iv, 0, GcmIvSize);
            Buffer.BlockCopy(data, GcmIvSize, cipherText, 0, cipherText.Length);

            var cipher = new GcmBlockCipher(new SM4Engine());
            var parameters = new AeadParameters(new KeyParameter(key), GcmTagSizeBits, iv);
            cipher.Init(false, parameters);

            var output = new byte[cipher.GetOutputSize(cipherText.Length)];
            int len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, output, 0);
            len += cipher.DoFinal(output, len);

            var result = new byte[len];
            Buffer.BlockCopy(output, 0, result, 0, len);
            return result;
        }

        /// <summary>
        /// SM4 GCM 加密（字符串输入），返回 Base64(IV[12] + 密文 + Tag[16])
        /// </summary>
        public static string EncryptGcmString(byte[] key, string plainText)
        {
            return EncryptGcm(key, EncodingUtils.Utf8GetBytes(plainText ?? string.Empty));
        }

        /// <summary>
        /// SM4 GCM 解密返回字符串
        /// </summary>
        public static string DecryptGcmToString(byte[] key, string ciphertextBase64)
        {
            return EncodingUtils.Utf8GetString(DecryptGcm(key, ciphertextBase64));
        }
    }
}
