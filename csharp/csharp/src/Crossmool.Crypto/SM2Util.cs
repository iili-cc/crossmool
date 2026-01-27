using System;
using System.Text;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
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

        static SM2Util()
        {
            var curve = GMNamedCurves.GetByName("sm2p256v1");
            Sm2Domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        }

        public static byte[] encrypt(byte[] originalTextBytes, byte[] publicKeyBytes)
        {
            if (originalTextBytes == null) throw new ArgumentNullException(nameof(originalTextBytes));
            if (publicKeyBytes == null) throw new ArgumentNullException(nameof(publicKeyBytes));

            var pubPoint = Sm2Domain.Curve.DecodePoint(publicKeyBytes);
            var pubKey = new ECPublicKeyParameters(pubPoint, Sm2Domain);
            var engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.Init(true, new ParametersWithRandom(pubKey, Rng));
            return engine.ProcessBlock(originalTextBytes, 0, originalTextBytes.Length);
        }

        public static string encrypt(string originalText, string publicKeyString)
        {
            var input = EncodingUtils.Utf8GetBytes(originalText ?? string.Empty);
            var pubBytes = EncodingUtils.ParseBase64OrHex(publicKeyString);
            var output = encrypt(input, pubBytes);
            return EncodingUtils.ToBase64(output);
        }

        public static string encryptToHex(string originalText, string publicKeyString)
        {
            var input = EncodingUtils.Utf8GetBytes(originalText ?? string.Empty);
            var pubBytes = EncodingUtils.ParseBase64OrHex(publicKeyString);
            var output = encrypt(input, pubBytes);
            return EncodingUtils.ToHex(output);
        }

        public static byte[] decrypt(byte[] encryptedTextBytes, byte[] privateKeyBytes)
        {
            if (encryptedTextBytes == null) throw new ArgumentNullException(nameof(encryptedTextBytes));
            if (privateKeyBytes == null) throw new ArgumentNullException(nameof(privateKeyBytes));

            var d = new BigInteger(1, privateKeyBytes);
            var privKey = new ECPrivateKeyParameters(d, Sm2Domain);
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

        public static string generateKeyPair()
        {
            var gen = new ECKeyPairGenerator();
            var keyGenParams = new ECKeyGenerationParameters(Sm2Domain, Rng);
            gen.Init(keyGenParams);
            var pair = gen.GenerateKeyPair();

            var priv = (ECPrivateKeyParameters)pair.Private;
            var pub = (ECPublicKeyParameters)pair.Public;

            var privBytes = priv.D.ToByteArrayUnsigned();
            var pubBytes = pub.Q.GetEncoded(false); // uncompressed 0x04 + X + Y

            var privHex = EncodingUtils.ToHex(privBytes);
            var pubHex = EncodingUtils.ToHex(pubBytes);
            // Return JSON for clarity
            return $"{{\"privateKeyHex\":\"{privHex}\",\"publicKeyHex\":\"{pubHex}\"}}";
        }

        // PEM helpers (PKCS#8 private key, SubjectPublicKeyInfo public key)
        public static string exportPrivateKeyPem(byte[] privateKeyBytes)
        {
            if (privateKeyBytes == null) throw new ArgumentNullException(nameof(privateKeyBytes));
            var d = new BigInteger(1, privateKeyBytes);
            var priv = new ECPrivateKeyParameters(d, Sm2Domain);
            var info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(priv);
            return ToPem("PRIVATE KEY", info.GetEncoded());
        }

        public static string exportPublicKeyPem(byte[] publicKeyBytes)
        {
            if (publicKeyBytes == null) throw new ArgumentNullException(nameof(publicKeyBytes));
            var q = Sm2Domain.Curve.DecodePoint(publicKeyBytes);
            var pub = new ECPublicKeyParameters(q, Sm2Domain);
            var info = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
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
    }
}
