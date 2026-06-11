
using System;
using System.Text.Json;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;

class Program {
    static string MSG = "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e";
    static string ENC_PUB = "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    static string ENC_PRIV = "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03";
    static string SIG_PUB = "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    static string SIG_PRIV = "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3";
    static string SM4_KEY = "0123456789abcdeffedcba9876543210";
    static string HMAC_KEY = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    static void Main() {
        var r = new System.Collections.Generic.Dictionary<string, object>();
        try {
            // SM2 Enc/Dec
            var c = SM2Util.encrypt(MSG, ENC_PUB);
            r["sm2_enc"] = c;
            var d = SM2Util.decrypt(c, ENC_PRIV);
            r["sm2_enc_dec"] = d == MSG ? "PASS" : "FAIL";
            // SM2 Sig/Ver
            var s = SM2Util.sign(MSG, SIG_PRIV);
            r["sm2_sig"] = s;
            r["sm2_sig_ver"] = SM2Util.verify(MSG, SIG_PUB, s) ? "PASS" : "FAIL";
            // SM3
            r["sm3_hash"] = SM3Util.digest(MSG);
            // SM3-HMAC
            r["sm3_hmac_hash"] = SM3Util.hmacToStr(HMAC_KEY, MSG);
            // SM4
            var sk = EncodingUtils.FromHex(SM4_KEY);
            var sc = SM4Util.EncryptGcmString(sk, MSG);
            r["sm4_enc"] = sc;
            var sd = SM4Util.DecryptGcmToString(sk, sc);
            r["sm4_enc_dec"] = sd == MSG ? "PASS" : "FAIL";
            var cross = new System.Collections.Generic.Dictionary<string, string> {
                {"sm2_enc", c}, {"sm2_sig", s}, {"sm4_enc", sc},
                {"sm3_hash", (string)r["sm3_hash"]}, {"sm3_hmac_hash", (string)r["sm3_hmac_hash"]}
            };
            r["cross"] = cross;
        } catch (Exception e) { r["error"] = e.Message; }
        Console.WriteLine(JsonSerializer.Serialize(r));
    }
}
