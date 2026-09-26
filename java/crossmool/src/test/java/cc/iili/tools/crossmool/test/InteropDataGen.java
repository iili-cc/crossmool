package cc.iili.tools.crossmool.test;
import cc.iili.tools.crossmool.tool.*;
import cc.iili.tools.crossmool.util.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class InteropDataGen {
    static String MSG = "Hello, 这是跨语言国密互通性测试数据";
    static String ENC_PRIV = "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03";
    static String ENC_PUB = "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    static String SIGN_PRIV = "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3";
    static String SIGN_PUB = "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    static String SM4_KEY_HEX = "0123456789abcdeffedcba9876543210";
    static String SM4_IV_HEX = "000102030405060708090a0b";
    static String HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

    public static void main(String[] args) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        
        // SM2 Encrypt
        String cipherHex = SM2Util.encrypt(MSG, ENC_PUB, false);
        String cipherB64 = SM2Util.encrypt(MSG, ENC_PUB, true);
        Map<String, String> sm2enc = new LinkedHashMap<>();
        sm2enc.put("cipher_hex", cipherHex);
        sm2enc.put("cipher_b64", cipherB64);
        result.put("sm2_encrypt", sm2enc);
        
        // SM2 Sign
        String sigHex = SM2Util.sign(MSG, SIGN_PRIV, false);
        String sigB64 = SM2Util.sign(MSG, SIGN_PRIV, true);
        Map<String, String> sm2sig = new LinkedHashMap<>();
        sm2sig.put("signature_hex", sigHex);
        sm2sig.put("signature_b64", sigB64);
        result.put("sm2_sign", sm2sig);
        
        // SM2 EncryptSign
        String sigOnCipher = SM2Util.sign(cipherHex, SIGN_PRIV, false);
        Map<String, String> sm2es = new LinkedHashMap<>();
        sm2es.put("cipher_hex", cipherHex);
        sm2es.put("signature_hex", sigOnCipher);
        result.put("sm2_encrypt_sign", sm2es);
        
        // SM3
        String digestHex = SM3Util.digestToStr(MSG);
        String digestB64 = SM3Util.digestToStr(MSG, true);
        Map<String, String> sm3 = new LinkedHashMap<>();
        sm3.put("digest_hex", digestHex);
        sm3.put("digest_b64", digestB64);
        result.put("sm3", sm3);
        
        // SM3-HMAC
        String hmacHex = SM3Util.hmacToStr(MSG, HMAC_KEY_HEX);
        String hmacB64 = SM3Util.hmacToStr(MSG, HMAC_KEY_HEX, true);
        Map<String, String> sm3hmac = new LinkedHashMap<>();
        sm3hmac.put("hmac_hex", hmacHex);
        sm3hmac.put("hmac_b64", hmacB64);
        result.put("sm3_hmac", sm3hmac);
        
        // SM4 GCM
        byte[] sm4Key = HexUtil.decodeHexStr(SM4_KEY_HEX);
        byte[] plainBytes = MSG.getBytes(StandardCharsets.UTF_8);
        String sm4Hex = SM4Util.encrypt(plainBytes, sm4Key, false);
        String sm4B64 = SM4Util.encrypt(plainBytes, sm4Key, true);
        Map<String, Object> sm4 = new LinkedHashMap<>();
        sm4.put("cipher_hex", sm4Hex);
        sm4.put("cipher_b64", sm4B64);
        sm4.put("key_hex", SM4_KEY_HEX);
        sm4.put("iv_hex", SM4_IV_HEX);
        result.put("sm4", sm4);
        
        System.out.println(new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(result));
    }
}
