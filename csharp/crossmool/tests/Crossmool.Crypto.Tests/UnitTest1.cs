using System;
using System.Text;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Crypto;
using Xunit;

namespace Crossmool.Crypto.Tests
{
    internal static class TestHelper
    {
        public static (string privateKeyHex, string publicKeyHex) GenerateKeyPair()
        {
            var kp = SM2Util.generateKeyPair();
            System.Diagnostics.Debug.WriteLine($"FULL JSON length={kp.Length}");
            System.Diagnostics.Debug.WriteLine($"JSON: {kp}");
            // Find the private key hex between the quotes after "privateKeyHex":
            var privTag = "\"privateKeyHex\":\"";
            var idx = kp.IndexOf(privTag);
            System.Diagnostics.Debug.WriteLine($"privTag idx={idx}");
            var pi = idx + privTag.Length;
            // Find closing quote — search for the pattern "," after which is "publicKeyHex"
            var pe = kp.IndexOf("\",\"publicKeyHex", pi);
            System.Diagnostics.Debug.WriteLine($"pi={pi}, pe={pe}, length={pe-pi}");
            var priv = kp[pi..pe];
            System.Diagnostics.Debug.WriteLine($"PRIV HEX: len={priv.Length}, val={priv}");
            // Public key
            var pubTag = "\"publicKeyHex\":\"";
            var ui = kp.IndexOf(pubTag) + pubTag.Length;
            var ue = kp.IndexOf("\"}", ui);
            var pub = kp[ui..ue];
            System.Diagnostics.Debug.WriteLine($"PUB HEX: len={pub.Length}, val={pub}");
            return (priv, pub);
        }
    }

    public class UtilsTests
    {
        [Fact] public void Hex_Roundtrip() { var b = new byte[] { 0xde, 0xad, 0xbe, 0xef }; var h = EncodingUtils.ToHex(b); Assert.Equal("deadbeef", h); Assert.Equal(b, EncodingUtils.FromHex(h)); }
        [Fact] public void Base64_Roundtrip() { var b = Encoding.UTF8.GetBytes("Hello"); var s = EncodingUtils.ToBase64(b); Assert.Equal("SGVsbG8=", s); Assert.Equal(b, EncodingUtils.FromBase64(s)); }
        [Fact] public void ParseBase64OrHex_Hex() { var b = EncodingUtils.ParseBase64OrHex("dead"); Assert.Equal(2, b.Length); Assert.Equal(0xde, b[0]); Assert.Equal(0xad, b[1]); }
        [Fact] public void ParseBase64OrHex_Base64() { var b = EncodingUtils.ParseBase64OrHex("SGVsbG8="); Assert.Equal("Hello", Encoding.UTF8.GetString(b)); }
        [Fact] public void LooksLikeHex_True() { Assert.True(EncodingUtils.LooksLikeHex("abcd1234")); }
        [Fact] public void LooksLikeHex_False() { Assert.False(EncodingUtils.LooksLikeHex("xyz")); }
        [Fact] public void Utf8_Roundtrip() { var b = EncodingUtils.Utf8GetBytes("测试"); Assert.Equal("测试", EncodingUtils.Utf8GetString(b)); }
    }

    public class SM2KeyGenTests
    {
        [Fact] public void GenerateKeyPair_ReturnsValidJson() { var kp = SM2Util.generateKeyPair(); Assert.Contains("privateKeyHex", kp); Assert.Contains("publicKeyHex", kp); }
        [Fact] public void GenerateKeyPair_KeysLookValid() { var (priv, pub) = TestHelper.GenerateKeyPair(); var msg = $"PRIVKEY(len={priv.Length}): {priv[..Math.Min(64, priv.Length)]}"; System.Diagnostics.Debug.WriteLine(msg); Console.WriteLine(msg); Assert.Equal(64, priv.Length); Assert.Equal(130, pub.Length); Assert.StartsWith("04", pub); }
    }

    public class SM2EncryptDecryptTests
    {
        [Fact] public void EncryptDecrypt_Roundtrip() { var (priv, pub) = TestHelper.GenerateKeyPair(); var ct = SM2Util.encrypt("Hello SM2!", pub); var pt = SM2Util.decrypt(ct, priv); Assert.Equal("Hello SM2!", pt); }
        [Fact] public void EncryptToHex_Roundtrip() { var (priv, pub) = TestHelper.GenerateKeyPair(); var ct = SM2Util.encryptToHex("Hello", pub); var pt = SM2Util.decrypt(ct, priv); Assert.Equal("Hello", pt); }
        [Fact] public void EncryptToBase64_Roundtrip() { var (priv, pub) = TestHelper.GenerateKeyPair(); var ct = SM2Util.encryptToBase64("World", pub); var pt = SM2Util.decrypt(ct, priv); Assert.Equal("World", pt); }
        [Fact] public void DecryptFromHex_Roundtrip() { var (priv, pub) = TestHelper.GenerateKeyPair(); var ct = SM2Util.encryptToHex("Hi", pub); var pt = SM2Util.decryptFromHex(ct, priv); Assert.Equal("Hi", pt); }
        [Fact] public void EncryptDecrypt_Bytes() { var (privHex, pubHex) = TestHelper.GenerateKeyPair(); var priv = EncodingUtils.FromHex(privHex); var pub = EncodingUtils.FromHex(pubHex); var ct = SM2Util.encrypt(Encoding.UTF8.GetBytes("Bytes"), pub); var pt = SM2Util.decrypt(ct, priv); Assert.Equal("Bytes", Encoding.UTF8.GetString(pt)); }
    }

    public class SM2SignVerifyTests
    {
        [Fact] public void SignVerify_Pass() { var (priv, pub) = TestHelper.GenerateKeyPair(); var sig = SM2Util.sign("Hello", priv); Assert.True(SM2Util.verify("Hello", sig, pub)); }
        [Fact] public void SignVerify_WrongMessage() { var (priv, pub) = TestHelper.GenerateKeyPair(); var sig = SM2Util.sign("Hello", priv); Assert.False(SM2Util.verify("World", sig, pub)); }
        [Fact] public void SignToHex_Verify() { var (priv, pub) = TestHelper.GenerateKeyPair(); var sig = SM2Util.signToHex("Test", priv); Assert.True(SM2Util.verify("Test", sig, pub)); }
        [Fact] public void SignToBase64_Verify() { var (priv, pub) = TestHelper.GenerateKeyPair(); var sig = SM2Util.signToBase64("Test", priv); Assert.True(SM2Util.verify("Test", sig, pub)); }
        [Fact] public void SignVerify_Bytes() { var (privHex, pubHex) = TestHelper.GenerateKeyPair(); var priv = EncodingUtils.FromHex(privHex); var pub = EncodingUtils.FromHex(pubHex); var sig = SM2Util.sign(Encoding.UTF8.GetBytes("Bytes"), priv); Assert.True(SM2Util.verify(Encoding.UTF8.GetBytes("Bytes"), sig, pub)); }
    }

    public class SM2EncryptSignTests
    {
        [Fact] public void EncryptSign_Combo() { var (encPriv, encPub) = TestHelper.GenerateKeyPair(); var (signPriv, signPub) = TestHelper.GenerateKeyPair(); var (ct, sig) = SM2Util.encryptSign("Combo", encPub, signPriv); var pt = SM2Util.verifyDecrypt(ct, sig, signPub, encPriv); Assert.Equal("Combo", pt); }
    }

    public class SM2PemTests
    {
        [Fact] public void Pem_ExportImport_Roundtrip() { var (privHex, pubHex) = TestHelper.GenerateKeyPair(); var privPem = SM2Util.exportPrivateKeyPem(EncodingUtils.FromHex(privHex)); var pubPem = SM2Util.exportPublicKeyPem(EncodingUtils.FromHex(pubHex)); var privBack = SM2Util.importPrivateKeyPem(privPem); var pubBack = SM2Util.importPublicKeyPem(pubPem); Assert.Equal(privHex.ToLowerInvariant(), EncodingUtils.ToHex(privBack)); Assert.Equal(pubHex.ToLowerInvariant(), EncodingUtils.ToHex(pubBack)); }
    }

    public class SM3DigestTests
    {
        [Fact] public void Digest_KnownVector_abc() { var h = SM3Util.digest("abc").ToLowerInvariant(); Assert.Equal("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", h); }
        [Fact] public void Digest_Length() { var h = SM3Util.digest("hello"); Assert.Equal(64, h.Length); }
        [Fact] public void DigestBase64_Length() { var h = SM3Util.digestBase64("hello"); Assert.True(h.Length > 0); }
        [Fact] public void Digest_Deterministic() { var h1 = SM3Util.digest("same"); var h2 = SM3Util.digest("same"); Assert.Equal(h1, h2); }
        [Fact] public void Digest_Bytes() { var hash = SM3Util.digest(Encoding.UTF8.GetBytes("test")); Assert.Equal(32, hash.Length); }
    }

    public class SM3HmacTests
    {
        [Fact] public void Hmac_Roundtrip() { var key = SM3Util.generateHmacKeyToStr(false); var h = SM3Util.hmacToStr(key, "data"); Assert.Equal(64, h.Length); }
        [Fact] public void Hmac_Base64() { var key = SM3Util.generateHmacKeyToStr(true); var h = SM3Util.hmacToStr(key, "data", true); Assert.True(h.Length > 0); }
        [Fact] public void GenerateHmacKey() { var key = SM3Util.generateHmacKey(32); Assert.Equal(32, key.Length); }
        [Fact] public void Hmac_Bytes() { var key = SM3Util.generateHmacKey(32); var data = Encoding.UTF8.GetBytes("test"); var mac = SM3Util.hmac(key, data); Assert.Equal(32, mac.Length); }
        [Fact] public void HmacToStr_Bytes() { var key = SM3Util.generateHmacKey(32); var data = Encoding.UTF8.GetBytes("test"); var h = SM3Util.hmacToStr(key, data); Assert.Equal(64, h.Length); }
    }

    public class SM4GcmTests
    {
        [Fact] public void Gcm_Hex_Roundtrip() { var key = SM4Util.GenerateKey(); var ct = SM4Util.EncryptGcm(key, Encoding.UTF8.GetBytes("Hello SM4")); var pt = SM4Util.DecryptGcm(key, ct); Assert.Equal("Hello SM4", Encoding.UTF8.GetString(pt)); }
        [Fact] public void Gcm_Base64_Roundtrip() { var key = SM4Util.GenerateKey(); var ct = SM4Util.EncryptGcm(key, Encoding.UTF8.GetBytes("Hello"), true); var pt = SM4Util.DecryptGcm(key, ct); Assert.Equal("Hello", Encoding.UTF8.GetString(pt)); }
        [Fact] public void Gcm_String_Roundtrip() { var key = SM4Util.GenerateKey(); var ct = SM4Util.EncryptGcmString(key, "String test"); var pt = SM4Util.DecryptGcmToString(key, ct); Assert.Equal("String test", pt); }
        [Fact] public void Gcm_EncryptGcmHex() { var key = SM4Util.GenerateKey(); var ct = SM4Util.EncryptGcmHex(key, Encoding.UTF8.GetBytes("Hex")); var pt = SM4Util.DecryptGcm(key, ct); Assert.Equal("Hex", Encoding.UTF8.GetString(pt)); }
        [Fact] public void Gcm_RandomIV() { var key = SM4Util.GenerateKey(); var b = Encoding.UTF8.GetBytes("test"); var ct1 = SM4Util.EncryptGcm(key, b); var ct2 = SM4Util.EncryptGcm(key, b); Assert.NotEqual(ct1, ct2); }
        [Fact] public void GenerateKeyAsHex() { var h = SM4Util.GenerateKeyAsHex(); Assert.Equal(32, h.Length); }
        [Fact] public void Gcm_Tamper_Throws() { var key = SM4Util.GenerateKey(); var ct = SM4Util.EncryptGcmString(key, "msg", true); var bytes = Convert.FromBase64String(ct); bytes[^1] ^= 0x01; Assert.Throws<InvalidCipherTextException>(() => SM4Util.DecryptGcmToString(key, Convert.ToBase64String(bytes))); }
    }
}
