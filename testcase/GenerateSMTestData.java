import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Java-C SM2/SM3/SM4 Interoperability Test - Test Data Generator
 */
public class GenerateSMTestData {
    
    private static final String TEST_MESSAGE = "Hello, Cross-Language Interop Test!";
    private static final String TEST_HMAC_KEY_HEX = "0123456789abcdef0123456789abcdef";
    
    public static void main(String[] args) throws Exception {
        System.out.println("Java-C SM2/SM3/SM4 Interoperability Test (Java side)");
        System.out.println("====================================================\n");
        
        // Generate SM2 keypair
        SerialKeyPair sm2Keys = SM2Util.generateKeyPairHex();
        System.out.println("SM2 Public Key:  " + sm2Keys.getPublicKey());
        System.out.println("SM2 Private Key: " + sm2Keys.getPrivateKey());
        
        // SM2 encrypt
        String sm2Ciphertext = SM2Util.encrypt(TEST_MESSAGE, sm2Keys.getPublicKey());
        System.out.println("SM2 Ciphertext:  " + sm2Ciphertext);
        
        // SM2 sign
        String sm2Signature = SM2Util.sign(TEST_MESSAGE, sm2Keys.getPrivateKey());
        System.out.println("SM2 Signature:   " + sm2Signature);
        
        // SM3 digest
        String sm3Digest = SM3Util.digestToStr(TEST_MESSAGE);
        System.out.println("SM3 Digest:      " + sm3Digest);
        
        // HMAC-SM3
        String hmacSm3 = SM3Util.hmacToStr(TEST_HMAC_KEY_HEX, TEST_MESSAGE);
        System.out.println("HMAC-SM3:        " + hmacSm3);
        
        // SM4 key and encrypt
        String sm4KeyHex = SM4Util.generateKeyAsHex();
        byte[] sm4Key = HexUtil.decodeHexStr(sm4KeyHex);
        String sm4Ciphertext = SM4Util.encryptEcbNative(sm4Key, TEST_MESSAGE.getBytes(StandardCharsets.UTF_8));
        System.out.println("SM4 Key:         " + sm4KeyHex);
        System.out.println("SM4 Ciphertext:  " + sm4Ciphertext);
        
        // Save test data to JSON
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"test_message\": \"").append(TEST_MESSAGE).append("\",\n");
        json.append("  \"sm2_public_key\": \"").append(sm2Keys.getPublicKey()).append("\",\n");
        json.append("  \"sm2_private_key\": \"").append(sm2Keys.getPrivateKey()).append("\",\n");
        json.append("  \"sm2_ciphertext\": \"").append(sm2Ciphertext).append("\",\n");
        json.append("  \"sm2_signature\": \"").append(sm2Signature).append("\",\n");
        json.append("  \"sm3_digest\": \"").append(sm3Digest).append("\",\n");
        json.append("  \"hmac_key_hex\": \"").append(TEST_HMAC_KEY_HEX).append("\",\n");
        json.append("  \"hmac_sm3\": \"").append(hmacSm3).append("\",\n");
        json.append("  \"sm4_key_hex\": \"").append(sm4KeyHex).append("\",\n");
        json.append("  \"sm4_ciphertext\": \"").append(sm4Ciphertext).append("\"\n");
        json.append("}\n");
        
        String outputPath = args.length > 0 ? args[0] : "test_data.json";
        Files.writeString(Paths.get(outputPath), json.toString());
        System.out.println("\nTest data saved to: " + outputPath);
        System.out.println("\nJava test data generation complete!");
    }
}