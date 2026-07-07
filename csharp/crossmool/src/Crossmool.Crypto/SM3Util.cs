using System;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Crossmool.Crypto
{
    public static class SM3Util
    {
        private static readonly SecureRandom Rng = new SecureRandom();

        #region Digest

        public static byte[] digest(byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            var d = new SM3Digest();
            d.BlockUpdate(input, 0, input.Length);
            var output = new byte[d.GetDigestSize()];
            d.DoFinal(output, 0);
            return output;
        }

        public static string digestToStr(byte[] input, bool toBase64 = false)
        {
            var hash = digest(input);
            return toBase64 ? EncodingUtils.ToBase64(hash) : EncodingUtils.ToHex(hash);
        }

        public static string digest(string input, bool toBase64 = false)
        {
            var bytes = EncodingUtils.Utf8GetBytes(input ?? string.Empty);
            var hash = digest(bytes);
            return toBase64 ? EncodingUtils.ToBase64(hash) : EncodingUtils.ToHex(hash);
        }

        public static string digestBase64(string input)
        {
            return digest(input, true);
        }

        #endregion

        #region HMAC

        public static byte[] hmac(byte[] key, byte[] data)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (data == null) throw new ArgumentNullException(nameof(data));

            var mac = new HMac(new SM3Digest());
            mac.Init(new KeyParameter(key));
            mac.BlockUpdate(data, 0, data.Length);
            var output = new byte[mac.GetMacSize()];
            mac.DoFinal(output, 0);
            return output;
        }

        public static byte[] hmac(string key, string data)
        {
            if (string.IsNullOrWhiteSpace(key)) throw new ArgumentException("Key cannot be empty", nameof(key));
            if (string.IsNullOrWhiteSpace(data)) throw new ArgumentException("Data cannot be empty", nameof(data));

            byte[] keyBytes = EncodingUtils.ParseBase64OrHex(key);
            byte[] dataBytes;
            if (EncodingUtils.LooksLikeHex(data))
            {
                dataBytes = EncodingUtils.FromHex(data);
            }
            else
            {
                try
                {
                    dataBytes = EncodingUtils.FromBase64(data);
                }
                catch (FormatException)
                {
                    dataBytes = EncodingUtils.Utf8GetBytes(data);
                }
            }
            return hmac(keyBytes, dataBytes);
        }

        public static string hmacToStr(byte[] key, byte[] data, bool toBase64 = false)
        {
            var result = hmac(key, data);
            return toBase64 ? EncodingUtils.ToBase64(result) : EncodingUtils.ToHex(result);
        }

        public static string hmacToStr(string key, string data, bool toBase64 = false)
        {
            var result = hmac(key, data);
            return toBase64 ? EncodingUtils.ToBase64(result) : EncodingUtils.ToHex(result);
        }

        #endregion

        #region HMAC Key Generation

        public static byte[] generateHmacKey(int keyLengthInBytes = 32)
        {
            if (keyLengthInBytes < 32)
                throw new ArgumentException("keyLengthInBytes must be >= 32", nameof(keyLengthInBytes));
            var key = new byte[keyLengthInBytes];
            Rng.NextBytes(key);
            return key;
        }

        public static string generateHmacKeyToStr(int keyLengthInBytes = 32, bool toBase64 = false)
        {
            var key = generateHmacKey(keyLengthInBytes);
            return toBase64 ? EncodingUtils.ToBase64(key) : EncodingUtils.ToHex(key);
        }

        public static string generateHmacKeyToStr(bool toBase64)
        {
            return generateHmacKeyToStr(32, toBase64);
        }

        public static bool hmacVerify(string key, string data, string receivedHmac)
        {
            return hmacToStr(key, data) == receivedHmac;
        }

        #endregion
    }
}