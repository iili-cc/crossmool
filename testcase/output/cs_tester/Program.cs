using System;
using System.Text.Json;
using System.IO;
using Crossmool.Crypto;

class InteropTest {
    static string MSG = "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e";
    static string SM2_ENC_PRIV = "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03";
    static string SM2_ENC_PUB = "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    static string SM2_SIG_PRIV = "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3";
    static string SM2_SIG_PUB = "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    static string SM4_KEY = "0123456789abcdeffedcba9876543210";
    static string HMAC_KEY = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    static string SM3_EXP = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b";
    static string SM3_HMAC_EXP = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";

    static void Main(string[] args) {
        var r = new System.Collections.Generic.Dictionary<string, object>();
        
        // SM3
        var sm3hex = SM3Util.digest(MSG);
        r["sm3"] = sm3hex;
        r["sm3_ok"] = sm3hex == SM3_EXP;
        
        // SM3-HMAC
        var hmacHex = SM3Util.hmacToStr(HMAC_KEY, MSG);
        r["sm3_hmac"] = hmacHex;
        r["sm3_hmac_ok"] = hmacHex == SM3_HMAC_EXP;
        
        try {
            // SM2 encrypt
            r["sm2_enc"] = SM2Util.encrypt(MSG, SM2_ENC_PUB);
            // SM2 sign
            r["sm2_sig"] = SM2Util.sign(MSG, SM2_SIG_PRIV);
            // SM4
            r["sm4_enc"] = SM4Util.EncryptGcmString(EncodingUtils.FromHex(SM4_KEY), MSG);
        } catch (Exception e) { r["error"] = e.Message; }
        
        // Verify reference
        if (args.Length > 0) {
            try {
                var refJson = File.ReadAllText(args[0]);
                using var doc = JsonDocument.Parse(refJson);
                var root = doc.RootElement;
                if (root.TryGetProperty("sm2_enc", out var refEnc)) {
                    var dec = SM2Util.decrypt(refEnc.GetString(), SM2_ENC_PRIV);
                    r["sm2_dec_ok"] = dec == MSG;
                }
                if (root.TryGetProperty("sm2_sig", out var refSig)) {
                    r["sm2_ver_ok"] = SM2Util.verify(MSG, SM2_SIG_PUB, refSig.GetString());
                }
                if (root.TryGetProperty("sm4_enc", out var refSm4)) {
                    var sm4Key = EncodingUtils.FromHex(SM4_KEY);
                    var dec = SM4Util.DecryptGcmToString(sm4Key, refSm4.GetString());
                    r["sm4_dec_ok"] = dec == MSG;
                }
            } catch (Exception e) { r["verify_error"] = e.Message; }
        }
        
        Console.WriteLine(JsonSerializer.Serialize(r));
    }
}
