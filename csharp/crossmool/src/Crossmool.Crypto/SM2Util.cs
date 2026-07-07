using System;
using System.Text;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Crossmool.Crypto
{
    public static class SM2Util
    {
        private static readonly ECDomainParameters Sm2Domain;
        private static readonly SecureRandom Rng = new SecureRandom();
        private static readonly byte[] UserId = Encoding.UTF8.GetBytes("1234567812345678");

        static SM2Util()
        {
            var curve = GMNamedCurves.GetByName("sm2p256v1");
            Sm2Domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        }

        #region Key Conversion Helpers

        private static ECPublicKeyParameters ParsePublicKey(byte[] keyBytes)
        {
            if (keyBytes == null || keyBytes.Length == 0)
                throw new ArgumentException("Public key bytes cannot be empty");

            if (keyBytes.Length == 65 && keyBytes[0] == 0x04)
            {
                var pubPoint = Sm2Domain.Curve.DecodePoint(keyBytes);
                return new ECPublicKeyParameters(pubPoint, Sm2Domain);
            }

            if (keyBytes[0] == 0x30)
            {
                var info = SubjectPublicKeyInfo.GetInstance(keyBytes);
                var key = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(info);
                return key;
            }

            try
            {
                var pubPoint = Sm2Domain.Curve.DecodePoint(keyBytes);
                return new ECPublicKeyParameters(pubPoint, Sm2Domain);
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Cannot parse public key (length={keyBytes.Length}, first byte=0x{keyBytes[0]:x2}): {ex.Message}", ex);
            }
        }

        private static ECPrivateKeyParameters ParsePrivateKey(byte[] keyBytes)
        {
            if (keyBytes == null || keyBytes.Length == 0)
                throw new ArgumentException("Private key bytes cannot be empty");

            // Pad short keys to 32 bytes (BouncyCastle may return < 32 from ToByteArrayUnsigned)
            if (keyBytes.Length < 32)
                keyBytes = PadPrivateKeyTo32(keyBytes);

            if (keyBytes.Length == 32)
            {
                var d = new BigInteger(1, keyBytes);
                return new ECPrivateKeyParameters(d, Sm2Domain);
            }

            if (keyBytes[0] == 0x30)
            {
                var info = PrivateKeyInfo.GetInstance(keyBytes);
                var key = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(info);
                return key;
            }

            try
            {
                var d = new BigInteger(1, keyBytes);
                return new ECPrivateKeyParameters(d, Sm2Domain);
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"Cannot parse private key (length={keyBytes.Length}, first byte=0x{keyBytes[0]:x2}): {ex.Message}", ex);
            }
        }

        #endregion

        #region Encrypt

        public static byte[] encrypt(byte[] originalTextBytes, byte[] publicKeyBytes)
        {
            if (originalTextBytes == null) throw new ArgumentNullException(nameof(originalTextBytes));
            if (publicKeyBytes == null) throw new ArgumentNullException(nameof(publicKeyBytes));

            var pubKey = ParsePublicKey(publicKeyBytes);
            var engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.Init(true, new ParametersWithRandom(pubKey, Rng));
            return engine.ProcessBlock(originalTextBytes, 0, originalTextBytes.Length);
        }

        public static string encrypt(string originalText, string publicKeyString, bool toBase64 = false)
        {
            var input = EncodingUtils.Utf8GetBytes(originalText ?? string.Empty);
            var pubBytes = EncodingUtils.ParseBase64OrHex(publicKeyString);
            var output = encrypt(input, pubBytes);
            return toBase64 ? EncodingUtils.ToBase64(output) : EncodingUtils.ToHex(output);
        }

        public static string encryptToHex(string originalText, string publicKeyString)
        {
            return encrypt(originalText, publicKeyString, false);
        }

        public static string encryptToBase64(string originalText, string publicKeyString)
        {
            return encrypt(originalText, publicKeyString, true);
        }

        #endregion

        #region Decrypt

        public static byte[] decrypt(byte[] encryptedTextBytes, byte[] privateKeyBytes)
        {
            if (encryptedTextBytes == null) throw new ArgumentNullException(nameof(encryptedTextBytes));
            if (privateKeyBytes == null) throw new ArgumentNullException(nameof(privateKeyBytes));

            var privKey = ParsePrivateKey(privateKeyBytes);
            var engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.Init(false, privKey);
            return engine.ProcessBlock(encryptedTextBytes, 0, encryptedTextBytes.Length);
        }

        public static string decrypt(string encryptedText, string privateKeyString)
        {
            var cipherBytes = EncodingUtils.ParseBase64OrHex(encryptedText);
            var privBytes = EncodingUtils.ParseBase64OrHex(privateKeyString);
            var plain = decrypt(cipherBytes, privBytes);
            return EncodingUtils.Utf8GetString(plain);
        }

        public static string decryptFromHex(string encryptedTextHex, string privateKeyString)
        {
            var cipherBytes = EncodingUtils.FromHex(encryptedTextHex);
            var privBytes = EncodingUtils.ParseBase64OrHex(privateKeyString);
            var plain = decrypt(cipherBytes, privBytes);
            return EncodingUtils.Utf8GetString(plain);
        }

        #endregion

        #region Sign

        public static byte[] sign(byte[] messageBytes, byte[] privateKeyBytes)
        {
            if (messageBytes == null) throw new ArgumentNullException(nameof(messageBytes));
            if (privateKeyBytes == null) throw new ArgumentNullException(nameof(privateKeyBytes));

            var privKey = ParsePrivateKey(privateKeyBytes);
            var signer = new SM2Signer();
            var parameters = new ParametersWithID(privKey, UserId);
            signer.Init(true, parameters);
            signer.BlockUpdate(messageBytes, 0, messageBytes.Length);
            return signer.GenerateSignature();
        }

        public static string sign(string message, string privateKeyString, bool toBase64 = false)
        {
            var messageBytes = EncodingUtils.Utf8GetBytes(message ?? string.Empty);
            var privBytes = EncodingUtils.ParseBase64OrHex(privateKeyString);
            var signature = sign(messageBytes, privBytes);
            return toBase64 ? EncodingUtils.ToBase64(signature) : EncodingUtils.ToHex(signature);
        }

        public static string signToHex(string message, string privateKeyString)
        {
            return sign(message, privateKeyString, false);
        }

        public static string signToBase64(string message, string privateKeyString)
        {
            return sign(message, privateKeyString, true);
        }

        #endregion

        #region Verify

        public static bool verify(byte[] messageBytes, byte[] signatureBytes, byte[] publicKeyBytes)
        {
            if (messageBytes == null) throw new ArgumentNullException(nameof(messageBytes));
            if (signatureBytes == null) throw new ArgumentNullException(nameof(signatureBytes));
            if (publicKeyBytes == null) throw new ArgumentNullException(nameof(publicKeyBytes));

            var pubKey = ParsePublicKey(publicKeyBytes);
            var signer = new SM2Signer();
            var parameters = new ParametersWithID(pubKey, UserId);
            signer.Init(false, parameters);
            signer.BlockUpdate(messageBytes, 0, messageBytes.Length);

            // Try raw signature first (DER or 64-byte RS)
            if (signer.VerifySignature(signatureBytes))
                return true;

            // If DER format, convert to 64-byte RS and try again
            if (signatureBytes.Length != 64 && signatureBytes.Length > 0 && signatureBytes[0] == 0x30)
            {
                try
                {
                    var rs = FromDerSignature(signatureBytes);
                    var rBytes = PadToLength(rs[0].ToByteArrayUnsigned(), 32);
                    var sBytes = PadToLength(rs[1].ToByteArrayUnsigned(), 32);
                    var sigBytes = new byte[64];
                    Array.Copy(rBytes, 0, sigBytes, 0, 32);
                    Array.Copy(sBytes, 0, sigBytes, 32, 32);

                    var signer2 = new SM2Signer();
                    signer2.Init(false, parameters);
                    signer2.BlockUpdate(messageBytes, 0, messageBytes.Length);
                    return signer2.VerifySignature(sigBytes);
                }
                catch
                {
                    return false;
                }
            }

            return false;
        }

        public static bool verify(string message, string signatureString, string publicKeyString)
        {
            var messageBytes = EncodingUtils.Utf8GetBytes(message ?? string.Empty);
            var signatureBytes = EncodingUtils.ParseBase64OrHex(signatureString);
            var pubBytes = EncodingUtils.ParseBase64OrHex(publicKeyString);
            return verify(messageBytes, signatureBytes, pubBytes);
        }

        #endregion

        #region EncryptSign

        public static (byte[] ciphertext, byte[] signature) encryptSign(byte[] messageBytes, byte[] publicKeyBytes, byte[] privateKeyBytes)
        {
            var ciphertext = encrypt(messageBytes, publicKeyBytes);
            // Sign the ciphertext hex string (UTF8 encoded), matching Java's behavior
            var ciphertextHex = EncodingUtils.ToHex(ciphertext);
            var signature = sign(EncodingUtils.Utf8GetBytes(ciphertextHex), privateKeyBytes);
            return (ciphertext, signature);
        }

        public static (string ciphertext, string signature) encryptSign(string message, string publicKeyString, string privateKeyString, bool toBase64 = false)
        {
            var messageBytes = EncodingUtils.Utf8GetBytes(message ?? string.Empty);
            var pubBytes = EncodingUtils.ParseBase64OrHex(publicKeyString);
            var privBytes = EncodingUtils.ParseBase64OrHex(privateKeyString);
            var (cipherBytes, sigBytes) = encryptSign(messageBytes, pubBytes, privBytes);
            return (
                toBase64 ? EncodingUtils.ToBase64(cipherBytes) : EncodingUtils.ToHex(cipherBytes),
                toBase64 ? EncodingUtils.ToBase64(sigBytes) : EncodingUtils.ToHex(sigBytes)
            );
        }

        #endregion

        #region VerifyDecrypt

        public static string verifyDecrypt(string ciphertextString, string signatureString, string signPublicKeyString, string decPrivateKeyString)
        {
            // Verify signature against ciphertext string (UTF8 encoded), matching Java's behavior
            bool verified = verify(ciphertextString, signatureString, signPublicKeyString);
            if (!verified)
            {
                throw new RuntimeException("SM2 verify failed: " + ciphertextString);
            }
            return decrypt(ciphertextString, decPrivateKeyString);
        }

        #endregion

        #region Key Generation

        public static string generateKeyPair()
        {
            var (pubHex, privHex) = generateKeyPairRaw();
            return $"{{\"privateKeyHex\":\"{privHex}\",\"publicKeyHex\":\"{pubHex}\"}}";
        }

        /// <summary>
        /// Generate SM2 key pair, return as hex strings.
        /// Public key: 130 chars (04+X+Y), Private key: 64 chars.
        /// </summary>
        public static (string publicKey, string privateKey) generateKeyPairHex()
        {
            return generateKeyPairRaw();
        }

        /// <summary>
        /// Generate SM2 key pair, return as base64 strings.
        /// </summary>
        public static (string publicKey, string privateKey) generateKeyPairBase64()
        {
            var (pubHex, privHex) = generateKeyPairRaw();
            return (EncodingUtils.ToBase64(EncodingUtils.FromHex(pubHex)),
                    EncodingUtils.ToBase64(EncodingUtils.FromHex(privHex)));
        }

        /// <summary>
        /// Generate SM2 key pair, return as (publicKeyHex, privateKeyHex) tuple.
        /// Public key: 130 chars (04+X+Y), Private key: 64 chars.
        /// </summary>
        internal static (string publicKey, string privateKey) generateKeyPairRaw()
        {
            var gen = new ECKeyPairGenerator();
            var keyGenParams = new ECKeyGenerationParameters(Sm2Domain, Rng);
            gen.Init(keyGenParams);
            var pair = gen.GenerateKeyPair();

            var priv = (ECPrivateKeyParameters)pair.Private;
            var pub = (ECPublicKeyParameters)pair.Public;

            // Pad private key to 32 bytes (BouncyCastle's ToByteArrayUnsigned may truncate leading zeros)
            var privBytes = PadPrivateKeyTo32(priv.D.ToByteArrayUnsigned());
            var pubBytes = pub.Q.GetEncoded(false);

            var privHex = EncodingUtils.ToHex(privBytes);
            var pubHex = EncodingUtils.ToHex(pubBytes);
            return (pubHex, privHex);
        }

        /// <summary>
        /// Pad private key bytes to 32 bytes (256 bits).
        /// BouncyCastle's ToByteArrayUnsigned() strips leading zeros.
        /// </summary>
        internal static byte[] PadPrivateKeyTo32(byte[] key)
        {
            if (key.Length == 32) return key;
            if (key.Length > 32) throw new ArgumentException($"Private key too long: {key.Length} bytes");
            var padded = new byte[32];
            Array.Copy(key, 0, padded, 32 - key.Length, key.Length);
            return padded;
        }

        #endregion

        #region PEM Import/Export

        public static string exportPrivateKeyPem(byte[] privateKeyBytes)
        {
            if (privateKeyBytes == null) throw new ArgumentNullException(nameof(privateKeyBytes));
            var privKey = ParsePrivateKey(privateKeyBytes);
            var info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey);
            return ToPem("PRIVATE KEY", info.GetEncoded());
        }

        public static string exportPublicKeyPem(byte[] publicKeyBytes)
        {
            if (publicKeyBytes == null) throw new ArgumentNullException(nameof(publicKeyBytes));
            var pubKey = ParsePublicKey(publicKeyBytes);
            var info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
            return ToPem("PUBLIC KEY", info.GetEncoded());
        }

        public static byte[] importPrivateKeyPem(string pem)
        {
            if (string.IsNullOrWhiteSpace(pem)) throw new ArgumentNullException(nameof(pem));
            var der = FromPem(pem, "PRIVATE KEY");
            var info = PrivateKeyInfo.GetInstance(der);
            var key = (ECPrivateKeyParameters)PrivateKeyFactory.CreateKey(info);
            return key.D.ToByteArrayUnsigned();
        }

        public static byte[] importPublicKeyPem(string pem)
        {
            if (string.IsNullOrWhiteSpace(pem)) throw new ArgumentNullException(nameof(pem));
            var der = FromPem(pem, "PUBLIC KEY");
            var info = SubjectPublicKeyInfo.GetInstance(der);
            var key = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(info);
            return key.Q.GetEncoded(false);
        }

        #endregion

        #region Private Helpers

        private static BigInteger[] FromDerSignature(byte[] der)
        {
            int pos = 0;
            if (der[pos++] != 0x30) throw new FormatException("Invalid DER signature");
            ReadDerLength(der, ref pos);
            if (der[pos++] != 0x02) throw new FormatException("Invalid DER signature");
            int rLen = ReadDerLength(der, ref pos);
            var rBytes = new byte[rLen];
            Array.Copy(der, pos, rBytes, 0, rLen);
            pos += rLen;
            if (der[pos++] != 0x02) throw new FormatException("Invalid DER signature");
            int sLen = ReadDerLength(der, ref pos);
            var sBytes = new byte[sLen];
            Array.Copy(der, pos, sBytes, 0, sLen);
            return new BigInteger[] { new BigInteger(1, rBytes), new BigInteger(1, sBytes) };
        }

        private static int ReadDerLength(byte[] buf, ref int pos)
        {
            int b = buf[pos++];
            if (b < 0x80) return b;
            int numBytes = b & 0x7f;
            int len = 0;
            for (int i = 0; i < numBytes; i++)
                len = (len << 8) | buf[pos++];
            return len;
        }

        private static byte[] PadToLength(byte[] data, int targetLength)
        {
            if (data.Length >= targetLength) return data;
            var result = new byte[targetLength];
            Array.Copy(data, 0, result, targetLength - data.Length, data.Length);
            return result;
        }

        private static string ToPem(string type, byte[] der)
        {
            var b64 = Convert.ToBase64String(der);
            var sb = new StringBuilder();
            sb.Append("-----BEGIN ").Append(type).AppendLine("-----");
            for (int i = 0; i < b64.Length; i += 64)
            {
                int len = Math.Min(64, b64.Length - i);
                sb.AppendLine(b64.Substring(i, len));
            }
            sb.Append("-----END ").Append(type).AppendLine("-----");
            return sb.ToString();
        }

        private static byte[] FromPem(string pem, string type)
        {
            var header = $"-----BEGIN {type}-----";
            var footer = $"-----END {type}-----";
            int start = pem.IndexOf(header, StringComparison.Ordinal);
            int end = pem.IndexOf(footer, StringComparison.Ordinal);
            if (start < 0 || end < 0 || end <= start)
                throw new FormatException($"PEM with {type} not found");
            start += header.Length;
            var base64 = pem.Substring(start, end - start);
            base64 = base64.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
            return Convert.FromBase64String(base64);
        }

        #endregion
    }

    public class RuntimeException : Exception
    {
        public RuntimeException(string message) : base(message) { }
        public RuntimeException(string message, Exception inner) : base(message, inner) { }
    }
}
