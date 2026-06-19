using System;
using System.Text;
using Crossmool.Crypto;
class Program {
    static string MSG = "Hello, 这是跨语言国密互通性测试数据";
    static string SM4_KEY = "0123456789abcdeffedcba9876543210";
    static string HMAC_KEY = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    static string EXP_SM3 = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b";
    static string EXP_SM3_HMAC = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";
    static string ENC_PUB = "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    static string ENC_PRIV = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    static string SIG_PUB = "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    static string SIG_PRIV = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    static void Main() {
        var sb = new StringBuilder();
        sb.Append("{\"lang\":\"csharp\"");
        try {
            var c = SM2Util.encrypt(MSG, ENC_PUB, false);
            sb.Append(",\"sm2_enc\":\"").Append(Escape(c)).Append("\"");
            var d = SM2Util.decrypt(c, ENC_PRIV);
            sb.Append(",\"sm2_enc_dec\":\"").Append(d==MSG?"PASS":"FAIL").Append("\"");
            Console.Error.WriteLine("SM2 enc/dec: " + (d==MSG?"PASS":"FAIL"));
        } catch(Exception e) { sb.Append(",\"sm2_enc_dec\":\"FAIL: ").Append(Escape(e.Message)).Append("\""); }
        try {
            var sig = SM2Util.sign(MSG, SIG_PRIV, false);
            sb.Append(",\"sm2_sig\":\"").Append(Escape(sig)).Append("\"");
            var ok = SM2Util.verify(MSG, sig, SIG_PUB);
            sb.Append(",\"sm2_sig_ver\":\"").Append(ok?"PASS":"FAIL").Append("\"");
            Console.Error.WriteLine("SM2 sign/verify: " + (ok?"PASS":"FAIL"));
        } catch(Exception e) { sb.Append(",\"sm2_sig_ver\":\"FAIL: ").Append(Escape(e.Message)).Append("\""); }
        try {
            var c2 = SM2Util.encrypt(MSG, ENC_PUB, false);
            var s2 = SM2Util.sign(MSG, SIG_PRIV, false);
            var d2 = SM2Util.decrypt(c2, ENC_PRIV);
            var ok2 = SM2Util.verify(d2, s2, SIG_PUB);
            sb.Append(",\"sm2_enc_sig_ver_dec\":\"").Append(d2==MSG&&ok2?"PASS":"FAIL").Append("\"");
            Console.Error.WriteLine("SM2 ES/VD: " + (d2==MSG&&ok2?"PASS":"FAIL"));
        } catch(Exception e) { sb.Append(",\"sm2_enc_sig_ver_dec\":\"FAIL: ").Append(Escape(e.Message)).Append("\""); }
        try {
            var h = SM3Util.digest(MSG, false);
            sb.Append(",\"sm3_hash\":\"").Append(h).Append("\"");
            sb.Append(",\"sm3\":\"").Append(h==EXP_SM3?"PASS":"FAIL").Append("\"");
            Console.Error.WriteLine("SM3: " + (h==EXP_SM3?"PASS":"FAIL"));
        } catch(Exception e) { sb.Append(",\"sm3\":\"FAIL: ").Append(Escape(e.Message)).Append("\""); }
        try {
            var hm = SM3Util.hmacToStr(HMAC_KEY, MSG, false);
            sb.Append(",\"sm3_hmac_hash\":\"").Append(hm).Append("\"");
            sb.Append(",\"sm3_hmac\":\"").Append(hm==EXP_SM3_HMAC?"PASS":"FAIL").Append("\"");
            Console.Error.WriteLine("SM3-HMAC: " + (hm==EXP_SM3_HMAC?"PASS":"FAIL"));
        } catch(Exception e) { sb.Append(",\"sm3_hmac\":\"FAIL: ").Append(Escape(e.Message)).Append("\""); }
        try {
            var sm4Key = Crossmool.Crypto.Utils.EncodingUtils.FromHex(SM4_KEY);
            var sc = SM4Util.EncryptGcmString(sm4Key, MSG, false);
            sb.Append(",\"sm4_enc\":\"").Append(Escape(sc)).Append("\"");
            var sd = SM4Util.DecryptGcmToString(sm4Key, sc);
            sb.Append(",\"sm4_enc_dec\":\"").Append(sd==MSG?"PASS":"FAIL").Append("\"");
            Console.Error.WriteLine("SM4 GCM: " + (sd==MSG?"PASS":"FAIL"));
        } catch(Exception e) { sb.Append(",\"sm4_enc_dec\":\"FAIL: ").Append(Escape(e.Message)).Append("\""); }
        sb.Append("}");
        Console.WriteLine(sb.ToString());
    }
    static string Escape(string s) { return s.Replace("\\","\\\\").Replace("\"","\\\"").Replace("\n","\n").Replace("\r",""); }
}
