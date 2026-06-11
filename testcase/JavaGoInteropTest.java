// No package declaration - run from testcase directory
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;
import java.nio.charset.StandardCharsets;

/**
 * Java-Go SM2/SM3/SM4 Interoperability Test Data Generator
 * 
 * Generates test data in both Hex and Base64 formats for Go verification.
 */
public class JavaGoInteropTest {
    
    public static void main(String[] args) throws Exception {
        System.out.println("============================================================");
        System.out.println("Java-Go SM2/SM3/SM4 Interoperability Test Data Generator");
        System.out.println("============================================================\n");
        
        String testMessage = "Hello, Java-Go Interop Test! 这是国密算法测试数据";
        String sm4KeyHex = "0123456789abcdeffedcba9876543210";
        String hmacKeyHex = "4ae2b84dd8cef6a39602edfa66f07b9970c79ca86a9641f3de4b7217f08e186c";
        
        // ========== SM2 Key Generation ==========
        System.out.println("Generating SM2 Keypair:");
        SerialKeyPair sm2Keys = SM2Util.generateKeyPairHex();
        String sm2PublicKey = sm2Keys.getPublicKey().trim();
        String sm2PrivateKey = sm2Keys.getPrivateKey().trim();
        System.out.println("SM2 Public Key (Hex): " + sm2PublicKey);
        System.out.println("SM2 Private Key (Hex): " + sm2PrivateKey);
        
        // ========== SM2 Encrypt/Decrypt (Hex) ==========
        System.out.println("\n--- SM2 Encrypt (Hex) ---");
        String sm2CipherHex = SM2Util.encrypt(testMessage, sm2PublicKey, false);
        System.out.println("SM2 Ciphertext (Hex): " + sm2CipherHex);
        
        String sm2DecryptedHex = SM2Util.decrypt(sm2CipherHex, sm2PrivateKey);
        System.out.println("SM2 Decrypted (Hex): " + sm2DecryptedHex);
        System.out.println("SM2 Hex Match: " + testMessage.equals(sm2DecryptedHex));
        
        // ========== SM2 Encrypt/Decrypt (Base64) ==========
        System.out.println("\n--- SM2 Encrypt (Base64) ---");
        String sm2CipherBase64 = SM2Util.encrypt(testMessage, sm2PublicKey, true);
        System.out.println("SM2 Ciphertext (Base64): " + sm2CipherBase64);
        
        String sm2DecryptedBase64 = SM2Util.decrypt(sm2CipherBase64, sm2PrivateKey);
        System.out.println("SM2 Decrypted (Base64): " + sm2DecryptedBase64);
        System.out.println("SM2 Base64 Match: " + testMessage.equals(sm2DecryptedBase64));
        
        // ========== SM2 Sign/Verify (Hex) ==========
        System.out.println("\n--- SM2 Sign (Hex) ---");
        String sm2SignHex = SM2Util.sign(testMessage, sm2PrivateKey, false);
        System.out.println("SM2 Signature (Hex): " + sm2SignHex);
        
        boolean sm2VerifyHex = SM2Util.verify(testMessage, sm2PublicKey, sm2SignHex);
        System.out.println("SM2 Verify (Hex): " + sm2VerifyHex);
        
        // ========== SM2 Sign/Verify (Base64) ==========
        System.out.println("\n--- SM2 Sign (Base64) ---");
        String sm2SignBase64 = SM2Util.sign(testMessage, sm2PrivateKey, true);
        System.out.println("SM2 Signature (Base64): " + sm2SignBase64);
        
        boolean sm2VerifyBase64 = SM2Util.verify(testMessage, sm2PublicKey, sm2SignBase64);
        System.out.println("SM2 Verify (Base64): " + sm2VerifyBase64);
        
        // ========== SM2 EncryptSign (Hex) ==========
        System.out.println("\n--- SM2 EncryptSign (Hex) ---");
        CiphertextSignaturePair csPairHex = SM2Util.encryptSign(testMessage, sm2PublicKey, sm2PrivateKey, false);
        System.out.println("SM2 Ciphertext (Hex): " + csPairHex.getCiphertext());
        System.out.println("SM2 Signature (Hex): " + csPairHex.getSignature());
        
        String sm2VerifyDecryptHex = SM2Util.verifyDecrypt(csPairHex, sm2PublicKey, sm2PrivateKey);
        System.out.println("SM2 VerifyDecrypt (Hex): " + sm2VerifyDecryptHex);
        System.out.println("SM2 EncryptSign Hex Match: " + testMessage.equals(sm2VerifyDecryptHex));
        
        // ========== SM2 EncryptSign (Base64) ==========
        System.out.println("\n--- SM2 EncryptSign (Base64) ---");
        CiphertextSignaturePair csPairBase64 = SM2Util.encryptSign(testMessage, sm2PublicKey, sm2PrivateKey, true);
        System.out.println("SM2 Ciphertext (Base64): " + csPairBase64.getCiphertext());
        System.out.println("SM2 Signature (Base64): " + csPairBase64.getSignature());
        
        String sm2VerifyDecryptBase64 = SM2Util.verifyDecrypt(csPairBase64, sm2PublicKey, sm2PrivateKey);
        System.out.println("SM2 VerifyDecrypt (Base64): " + sm2VerifyDecryptBase64);
        System.out.println("SM2 EncryptSign Base64 Match: " + testMessage.equals(sm2VerifyDecryptBase64));
        
        // ========== SM3 Digest ==========
        System.out.println("\n--- SM3 Digest ---");
        String sm3DigestHex = SM3Util.digestToStr(testMessage, false);
        String sm3DigestBase64 = SM3Util.digestToStr(testMessage, true);
        System.out.println("SM3 Digest (Hex): " + sm3DigestHex);
        System.out.println("SM3 Digest (Base64): " + sm3DigestBase64);
        
        // ========== HMAC-SM3 ==========
        System.out.println("\n--- HMAC-SM3 ---");
        byte[] hmacKeyBytes = HexUtil.decodeHexStr(hmacKeyHex);
        String hmacHex = SM3Util.hmacToStr(hmacKeyBytes, testMessage.getBytes(StandardCharsets.UTF_8), false);
        String hmacBase64 = SM3Util.hmacToStr(hmacKeyBytes, testMessage.getBytes(StandardCharsets.UTF_8), true);
        System.out.println("HMAC-SM3 (Hex): " + hmacHex);
        System.out.println("HMAC-SM3 (Base64): " + hmacBase64);
        
        // Also test with string key
        String hmacStrHex = SM3Util.hmacToStr(hmacKeyHex, testMessage, false);
        String hmacStrBase64 = SM3Util.hmacToStr(hmacKeyHex, testMessage, true);
        System.out.println("HMAC-SM3 (String Key, Hex): " + hmacStrHex);
        System.out.println("HMAC-SM3 (String Key, Base64): " + hmacStrBase64);
        
        // ========== SM4 GCM Encrypt/Decrypt ==========
        System.out.println("\n--- SM4 GCM Encrypt/Decrypt ---");
        byte[] sm4KeyBytes = HexUtil.decodeHexStr(sm4KeyHex);
        
        // Hex
        String sm4CipherHex = SM4Util.encrypt(sm4KeyHex, testMessage, false);
        System.out.println("SM4 GCM Ciphertext (Hex): " + sm4CipherHex);
        
        String sm4DecryptedHex = SM4Util.decrypt(sm4KeyHex, sm4CipherHex);
        System.out.println("SM4 GCM Decrypted (Hex): " + sm4DecryptedHex);
        System.out.println("SM4 GCM Hex Match: " + testMessage.equals(sm4DecryptedHex));
        
        // Base64
        String sm4CipherBase64 = SM4Util.encrypt(sm4KeyHex, testMessage, true);
        System.out.println("SM4 GCM Ciphertext (Base64): " + sm4CipherBase64);
        
        String sm4DecryptedBase64 = SM4Util.decrypt(sm4KeyHex, sm4CipherBase64);
        System.out.println("SM4 GCM Decrypted (Base64): " + sm4DecryptedBase64);
        System.out.println("SM4 GCM Base64 Match: " + testMessage.equals(sm4DecryptedBase64));
        
        // ========== Output JSON for Go Verification ==========
        System.out.println("\n");
        System.out.println("========== JAVA_OUTPUT_JSON_START ==========");
        System.out.println("{");
        System.out.println("  \"test_message\": \"" + escapeJson(testMessage) + "\",");
        System.out.println("  \"sm2_public_key_hex\": \"" + sm2PublicKey + "\",");
        System.out.println("  \"sm2_private_key_hex\": \"" + sm2PrivateKey + "\",");
        System.out.println("  \"sm2_ciphertext_hex\": \"" + sm2CipherHex + "\",");
        System.out.println("  \"sm2_ciphertext_base64\": \"" + sm2CipherBase64 + "\",");
        System.out.println("  \"sm2_signature_hex\": \"" + sm2SignHex + "\",");
        System.out.println("  \"sm2_signature_base64\": \"" + sm2SignBase64 + "\",");
        System.out.println("  \"sm2_cs_ciphertext_hex\": \"" + csPairHex.getCiphertext() + "\",");
        System.out.println("  \"sm2_cs_signature_hex\": \"" + csPairHex.getSignature() + "\",");
        System.out.println("  \"sm2_cs_ciphertext_base64\": \"" + csPairBase64.getCiphertext() + "\",");
        System.out.println("  \"sm2_cs_signature_base64\": \"" + csPairBase64.getSignature() + "\",");
        System.out.println("  \"sm3_digest_hex\": \"" + sm3DigestHex + "\",");
        System.out.println("  \"sm3_digest_base64\": \"" + sm3DigestBase64 + "\",");
        System.out.println("  \"hmac_key_hex\": \"" + hmacKeyHex + "\",");
        System.out.println("  \"hmac_hex\": \"" + hmacHex + "\",");
        System.out.println("  \"hmac_base64\": \"" + hmacBase64 + "\",");
        System.out.println("  \"sm4_key_hex\": \"" + sm4KeyHex + "\",");
        System.out.println("  \"sm4_gcm_ciphertext_hex\": \"" + sm4CipherHex + "\",");
        System.out.println("  \"sm4_gcm_ciphertext_base64\": \"" + sm4CipherBase64 + "\"");
        System.out.println("}");
        System.out.println("========== JAVA_OUTPUT_JSON_END ==========");
        
        // ========== Summary ==========
        System.out.println("\n============================================================");
        System.out.println("Java Self-Test Summary");
        System.out.println("============================================================");
        boolean allPass = sm2DecryptedHex.equals(testMessage) &&
                          sm2DecryptedBase64.equals(testMessage) &&
                          sm2VerifyHex && sm2VerifyBase64 &&
                          sm2VerifyDecryptHex.equals(testMessage) &&
                          sm2VerifyDecryptBase64.equals(testMessage) &&
                          sm4DecryptedHex.equals(testMessage) &&
                          sm4DecryptedBase64.equals(testMessage);
        
        if (allPass) {
            System.out.println("[SUCCESS] All Java self-tests passed!");
        } else {
            System.out.println("[FAIL] Some Java self-tests failed!");
            System.exit(1);
        }
    }
    
    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}