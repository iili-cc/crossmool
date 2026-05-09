
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.*;
import cc.iili.tools.crossmool.util.HexUtil;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class GenerateTestData {
    public static void main(String[] args) throws Exception {
        System.out.println("Generating Java test data...");
        
        String testMessage = "Hello, Cross-Language Interop Test! 测试消息 123456";
        String hmacKeyHex = "0123456789abcdef0123456789abcdef";
        
        // 生成 SM2 密钥对
        SerialKeyPair sm2Keys = SM2Util.generateKeyPairHex();
        System.out.println("SM2 Public Key: " + sm2Keys.getPublicKey());
        System.out.println("SM2 Private Key: " + sm2Keys.getPrivateKey());
        
        // SM2 加密
        String sm2Ciphertext = SM2Util.encrypt(testMessage, sm2Keys.getPublicKey());
        System.out.println("SM2 Ciphertext: " + sm2Ciphertext);
        
        // SM2 签名
        String sm2Signature = SM2Util.sign(testMessage, sm2Keys.getPrivateKey());
        System.out.println("SM2 Signature: " + sm2Signature);
        
        // SM3 摘要
        String sm3Digest = SM3Util.digestToStr(testMessage);
        System.out.println("SM3 Digest: " + sm3Digest);
        
        // HMAC-SM3
        String hmacSm3 = SM3Util.hmacToStr(hmacKeyHex, testMessage);
        System.out.println("HMAC-SM3: " + hmacSm3);
        
        // SM4 密钥和加密
        String sm4KeyHex = SM4Util.generateKeyAsHex();
        byte[] sm4Key = HexUtil.decodeHexStr(sm4KeyHex);
        String sm4Ciphertext = SM4Util.encryptEcbNative(sm4Key, testMessage.getBytes(StandardCharsets.UTF_8));
        System.out.println("SM4 Key: " + sm4KeyHex);
        System.out.println("SM4 Ciphertext: " + sm4Ciphertext);
        
        // 保存测试数据到 JSON
        Map<String, String> data = new HashMap<>();
        data.put("test_message", testMessage);
        data.put("sm2_public_key", sm2Keys.getPublicKey());
        data.put("sm2_private_key", sm2Keys.getPrivateKey());
        data.put("sm2_ciphertext", sm2Ciphertext);
        data.put("sm2_signature", sm2Signature);
        data.put("sm3_digest", sm3Digest);
        data.put("hmac_key_hex", hmacKeyHex);
        data.put("hmac_sm3", hmacSm3);
        data.put("sm4_key_hex", sm4KeyHex);
        data.put("sm4_ciphertext", sm4Ciphertext);
        
        String json = "{" + String.join(",", 
            ""test_message":"" + data.get("test_message") + """,
            ""sm2_public_key":"" + data.get("sm2_public_key") + """,
            ""sm2_private_key":"" + data.get("sm2_private_key") + """,
            ""sm2_ciphertext":"" + data.get("sm2_ciphertext") + """,
            ""sm2_signature":"" + data.get("sm2_signature") + """,
            ""sm3_digest":"" + data.get("sm3_digest") + """,
            ""hmac_key_hex":"" + data.get("hmac_key_hex") + """,
            ""hmac_sm3":"" + data.get("hmac_sm3") + """,
            ""sm4_key_hex":"" + data.get("sm4_key_hex") + """,
            ""sm4_ciphertext":"" + data.get("sm4_ciphertext") + """
        ) + "}";
        
        Files.writeString(Paths.get("test_data.json"), json);
        System.out.println("Test data saved to test_data.json");
        System.out.println("Java test data generation complete!");
    }
}
