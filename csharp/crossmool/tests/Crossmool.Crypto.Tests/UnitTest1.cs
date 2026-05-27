using System;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Crypto;
using Xunit;

namespace Crossmool.Crypto.Tests
{

public class SM3Tests
{
    [Fact]
    public void SM3_abc_KnownVector()
    {
        var hex = SM3Util.digest("abc").ToLowerInvariant();
        const string expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
        Assert.Equal(expected, hex);
    }
}

public class SM2Tests
{
    [Fact]
    public void SM2_Roundtrip_Base64_and_Hex()
    {
        var kpJson = SM2Util.generateKeyPair();
        var priv = ExtractJson(kpJson, "privateKeyHex");
        var pub = ExtractJson(kpJson, "publicKeyHex");

        var msg = "Hello SM2";
        var cB64 = SM2Util.encrypt(msg, pub);
        var p1 = SM2Util.decrypt(cB64, priv);
        Assert.Equal(msg, p1);

        var cHex = SM2Util.encryptToHex(msg, pub);
        var p2 = SM2Util.decryptFromHex(cHex, priv);
        Assert.Equal(msg, p2);
    }

    [Fact]
    public void SM2_Pem_Export_Import_Roundtrip()
    {
        var kpJson = SM2Util.generateKeyPair();
        var privHex = ExtractJson(kpJson, "privateKeyHex");
        var pubHex = ExtractJson(kpJson, "publicKeyHex");

        var privBytes = EncodingUtils.FromHex(privHex);
        var pubBytes = EncodingUtils.FromHex(pubHex);

        var privPem = SM2Util.exportPrivateKeyPem(privBytes);
        var pubPem = SM2Util.exportPublicKeyPem(pubBytes);

        var privImported = SM2Util.importPrivateKeyPem(privPem);
        var pubImported = SM2Util.importPublicKeyPem(pubPem);

        Assert.Equal(privHex.ToLowerInvariant(), EncodingUtils.ToHex(privImported));
        Assert.Equal(pubHex.ToLowerInvariant(), EncodingUtils.ToHex(pubImported));

        // Ensure imported keys still work
        var msg = "PEM roundtrip";
        var cipher = SM2Util.encrypt(EncodingUtils.Utf8GetBytes(msg), pubImported);
        var plain = SM2Util.decrypt(cipher, privImported);
        Assert.Equal(msg, EncodingUtils.Utf8GetString(plain));
    }

    private static string ExtractJson(string json, string key)
    {
        var tag = $"\"{key}\":\"";
        var idx = json.IndexOf(tag, StringComparison.Ordinal);
        Assert.True(idx >= 0, $"Key {key} not found");
        idx += tag.Length;
        var end = json.IndexOf('"', idx);
        if (end < 0) end = json.Length;
        return json.Substring(idx, end - idx);
    }
}

public class SM4Tests
{
    // Key used for cross-language tests: ad1486d58d4e012d4c94936616ecf7d6
    private const string CrossLangKeyHex = "ad1486d58d4e012d4c94936616ecf7d6";
    private const string CrossLangMessage = "Hello, 這是国密SM4測試數據";

    [Fact]
    public void SM4_Gcm_Roundtrip_Base64()
    {
        var keyHex = "00112233445566778899aabbccddeeff";
        var key = EncodingUtils.FromHex(keyHex);
        var msg = "Hello SM4 GCM";
        var cB64 = SM4Util.EncryptGcmString(key, msg);
        var p1 = SM4Util.DecryptGcmToString(key, cB64);
        Assert.Equal(msg, p1);
    }

    [Fact]
    public void SM4_Gcm_Roundtrip_Bytes()
    {
        var keyHex = "00112233445566778899aabbccddeeff";
        var key = EncodingUtils.FromHex(keyHex);
        var plaintext = EncodingUtils.Utf8GetBytes("Hello SM4 GCM bytes");
        var cB64 = SM4Util.EncryptGcm(key, plaintext);
        var decrypted = SM4Util.DecryptGcm(key, cB64);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void SM4_Gcm_Tamper_Throws_InvalidCipherTextException()
    {
        var keyHex = "00112233445566778899aabbccddeeff";
        var key = EncodingUtils.FromHex(keyHex);
        var msg = "GCM tamper test";
        var cB64 = SM4Util.EncryptGcmString(key, msg);

        var cipherBytes = Convert.FromBase64String(cB64);
        cipherBytes[cipherBytes.Length - 1] ^= 0x01;
        var tamperedB64 = Convert.ToBase64String(cipherBytes);

        Assert.Throws<InvalidCipherTextException>(() =>
            SM4Util.DecryptGcmToString(key, tamperedB64));
    }

    [Fact]
    public void SM4_Gcm_Decrypt_Java_Native_Ciphertext()
    {
        var key = EncodingUtils.FromHex(CrossLangKeyHex);
        // Java Native GCM ciphertext (key=ad1486d58d4e012d4c94936616ecf7d6, plaintext="Hello, 這是国密SM4測試數據")
        var javaNativeCt = "9ud33pnp80PrjMCaf7i25R/mZVve+eEjrddhu4fv19axPD/jhLAEaVQfT9i8/2jJxIWR00cjk8LYmVbityo=";
        var pt = SM4Util.DecryptGcmToString(key, javaNativeCt);
        Assert.Equal(CrossLangMessage, pt);
    }

    [Fact]
    public void SM4_Gcm_Decrypt_Java_JCA_Ciphertext()
    {
        var key = EncodingUtils.FromHex(CrossLangKeyHex);
        // Java JCA GCM ciphertext (key=ad1486d58d4e012d4c94936616ecf7d6, plaintext="Hello, 這是国密SM4測試數據")
        var javaJcaCt = "zwDiv77YRtE1H/f0aBGKCKyUrC/A5oYqnB3ZHHCektCW28HsO3pszlRvtKQF1LHugKILvIdlLy8ooMrr/Zc=";
        var pt = SM4Util.DecryptGcmToString(key, javaJcaCt);
        Assert.Equal(CrossLangMessage, pt);
    }
}
}
