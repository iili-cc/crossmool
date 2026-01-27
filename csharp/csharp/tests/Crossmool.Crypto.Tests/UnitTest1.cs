using System;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;
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
    [Fact]
    public void SM4_Roundtrip_Base64_and_Hex()
    {
        var keyHex = "00112233445566778899aabbccddeeff"; // 16 bytes
        var msg = "Hello SM4";
        var cB64 = SM4Util.encrypt(msg, keyHex);
        var p1 = SM4Util.decrypt(cB64, keyHex);
        Assert.Equal(msg, p1);

        var cHex = SM4Util.encryptToHex(msg, keyHex);
        var p2 = SM4Util.decryptFromHex(cHex, keyHex);
        Assert.Equal(msg, p2);
    }
}
}
