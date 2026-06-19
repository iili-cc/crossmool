import java.nio.charset.StandardCharsets;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;
public class SelfTest {
    static String MSG = "\u4F60\u597D\uFF0C\u8FD9\u662F\u8DE8\u8BED\u8A00\u56FD\u5BC6\u4E92\u901A\u6027\u6D4B\u8BD5\u6570\u636E";
    static String SM4_KEY_HEX = "0123456789abcdeffedcba9876543210";
    static String HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    static String EXP_SM3 = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b";
    static String EXP_SM3_HMAC = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";
    static String ENC_PUB = "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    static String ENC_PRIV = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    static String SIG_PUB = "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    static String SIG_PRIV = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    public static void main(String[] args) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"lang\":\"java\"");
        try {
            String c = SM2Util.encrypt(MSG, ENC_PUB, false);
            sb.append(",\"sm2_enc\":\"").append(escape(c)).append("\"");
            String d = SM2Util.decrypt(c, ENC_PRIV);
            sb.append(",\"sm2_enc_dec\":\"").append(d.equals(MSG)?"PASS":"FAIL").append("\"");
            System.err.println("SM2 Enc/Dec: " + (d.equals(MSG)?"PASS":"FAIL"));
        } catch (Exception e) { sb.append(",\"sm2_enc_dec\":\"FAIL: ").append(escape(e.getMessage())).append("\""); System.err.println("SM2 Enc/Dec FAIL: " + e.getMessage()); }
        try {
            String sig = SM2Util.sign(MSG, SIG_PRIV, false);
            sb.append(",\"sm2_sig\":\"").append(escape(sig)).append("\"");
            boolean ok = SM2Util.verify(MSG, SIG_PUB, sig);
            sb.append(",\"sm2_sig_ver\":\"").append(ok?"PASS":"FAIL").append("\"");
            System.err.println("SM2 Sign/Verify: " + (ok?"PASS":"FAIL"));
        } catch (Exception e) { sb.append(",\"sm2_sig_ver\":\"FAIL: ").append(escape(e.getMessage())).append("\""); System.err.println("SM2 Sign/Verify FAIL: " + e.getMessage()); }
        try {
            String c2 = SM2Util.encrypt(MSG, ENC_PUB, false);
            String s2 = SM2Util.sign(MSG, SIG_PRIV, false);
            String d2 = SM2Util.decrypt(c2, ENC_PRIV);
            boolean ok2 = SM2Util.verify(d2, SIG_PUB, s2);
            sb.append(",\"sm2_enc_sig_ver_dec\":\"").append(d2.equals(MSG)&&ok2?"PASS":"FAIL").append("\"");
            System.err.println("SM2 EncSign/VerifyDec: " + (d2.equals(MSG)&&ok2?"PASS":"FAIL"));
        } catch (Exception e) { sb.append(",\"sm2_enc_sig_ver_dec\":\"FAIL: ").append(escape(e.getMessage())).append("\""); }
        try {
            String h = SM3Util.digestToStr(MSG, false);
            sb.append(",\"sm3_hash\":\"").append(h).append("\"");
            sb.append(",\"sm3\":\"").append(h.equals(EXP_SM3)?"PASS":"FAIL").append("\"");
            System.err.println("SM3: " + (h.equals(EXP_SM3)?"PASS":"FAIL"));
        } catch (Exception e) { sb.append(",\"sm3\":\"FAIL: ").append(escape(e.getMessage())).append("\""); System.err.println("SM3 FAIL: " + e.getMessage()); }
        try {
            String hm = SM3Util.hmacToStr(HMAC_KEY_HEX, MSG, false);
            sb.append(",\"sm3_hmac_hash\":\"").append(hm).append("\"");
            sb.append(",\"sm3_hmac\":\"").append(hm.equals(EXP_SM3_HMAC)?"PASS":"FAIL").append("\"");
            System.err.println("SM3-HMAC: " + (hm.equals(EXP_SM3_HMAC)?"PASS":"FAIL"));
        } catch (Exception e) { sb.append(",\"sm3_hmac\":\"FAIL: ").append(escape(e.getMessage())).append("\""); }
        try {
            byte[] sm4Key = HexUtil.decodeHexStr(SM4_KEY_HEX);
            String sc = SM4Util.encrypt(sm4Key, MSG.getBytes(StandardCharsets.UTF_8), false);
            sb.append(",\"sm4_enc\":\"").append(escape(sc)).append("\"");
            String sd = SM4Util.decrypt(sm4Key, sc);
            sb.append(",\"sm4_enc_dec\":\"").append(sd.equals(MSG)?"PASS":"FAIL").append("\"");
            System.err.println("SM4 GCM: " + (sd.equals(MSG)?"PASS":"FAIL"));
        } catch (Exception e) { sb.append(",\"sm4_enc_dec\":\"FAIL: ").append(escape(e.getMessage())).append("\""); System.err.println("SM4 GCM FAIL: " + e.getMessage()); }
        sb.append("}");
        System.out.println(sb.toString());
    }
    static String escape(String s) { return s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\n").replace("\r",""); }
}
