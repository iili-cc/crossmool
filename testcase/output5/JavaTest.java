
import cc.iili.tools.crossmool.tool.*;
import cc.iili.tools.crossmool.util.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class JavaTest {
    static String MSG = "Hello, 这是跨语言国密互通性测试数据";
    static String ENC_PUB = "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    static String ENC_PRIV = "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03";
    static String SIG_PUB = "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    static String SIG_PRIV = "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3";
    static String SM4_KEY = "0123456789abcdeffedcba9876543210";
    static String HMAC_KEY = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    public static void main(String[] args) throws Exception {
        Map<String,Object> r = new LinkedHashMap<>();
        
        // SM2 Enc/Dec
        String c = SM2Util.encrypt(MSG, ENC_PUB, false);
        r.put("sm2_enc", c);
        String d = SM2Util.decrypt(c, ENC_PRIV);
        r.put("sm2_enc_dec", d.equals(MSG) ? "PASS" : "FAIL");
        
        // SM2 Sig/Ver
        String s = SM2Util.sign(MSG, SIG_PRIV, false);
        r.put("sm2_sig", s);
        boolean ok = SM2Util.verify(MSG, SIG_PUB, s);
        r.put("sm2_sig_ver", ok ? "PASS" : "FAIL");
        
        // SM3
        String dig = SM3Util.digestToStr(MSG);
        r.put("sm3_hash", dig);
        
        // SM3-HMAC
        String hmac = SM3Util.hmacToStr(HMAC_KEY, MSG);
        r.put("sm3_hmac_hash", hmac);
        
        // SM4
        byte[] sk = HexUtil.decodeHexStr(SM4_KEY);
        byte[] pb = MSG.getBytes(StandardCharsets.UTF_8);
        String sc = SM4Util.encrypt(sk, pb, false);
        r.put("sm4_enc", sc);
        String sd = SM4Util.decrypt(sk, sc);
        r.put("sm4_enc_dec", sd.equals(MSG) ? "PASS" : "FAIL");
        
        Map<String,String> cross = new LinkedHashMap<>();
        cross.put("sm2_enc", c);
        cross.put("sm2_sig", s);
        cross.put("sm4_enc", sc);
        cross.put("sm3_hash", dig);
        cross.put("sm3_hmac_hash", hmac);
        r.put("cross", cross);
        
        // Simple JSON output
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        for (String key : r.keySet()) {
            Object v = r.get(key);
            sb.append("\"").append(key).append("\":");
            if (v instanceof String) sb.append("\"").append(v).append("\"");
            else if (v instanceof Map) {
                Map<?,?> m = (Map<?,?>)v;
                sb.append("{");
                boolean first = true;
                for (Object mk : m.keySet()) {
                    if (!first) sb.append(",");
                    sb.append("\"").append(mk).append("\":\"").append(m.get(mk)).append("\"");
                    first = false;
                }
                sb.append("}");
            }
            else sb.append("\"").append(v).append("\"");
            sb.append(",");
        }
        // remove last comma
        if (sb.charAt(sb.length()-1) == ',') sb.setLength(sb.length()-1);
        sb.append("}");
        System.out.println(sb.toString());
    }
}
