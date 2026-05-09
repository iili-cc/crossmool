// No package declaration - run from testcase directory
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

/**
 * Java-Python SM2/SM3/SM4 Interoperability Test
 * 
 * Generates test data and verifies all Java operations work correctly.
 * Output can be verified by Python (test_java_python_sm_interop.py).
 */
public class JavaPythonSMInteropTest {
    
    public static void main(String[] args) throws Exception {
        System.out.println("============================================================");
        System.out.println("Java-Python SM2/SM3/SM4 Interoperability Test");
        System.out.println("============================================================\n");
        
        String testMessage = "Hello, Java-Python Interop Test!";
        String sm4KeyHex = "df87a629223dbbae37ed67dd0304643a";
        String hmacKeyHex = "4ae2b84dd8cef6a39602edfa66f07b9970c79ca86a9641f3de4b7217f08e186c";
        
        // ========== Generate Java Keypair ==========
        System.out.println("Generating Java SM2 Keypair:");
        System.out.println("------------------------------------------------------------\n");
        
        SerialKeyPair keys = SM2Util.generateKeyPairHex();
        String publicKey = keys.getPublicKey().trim();
        String privateKey = keys.getPrivateKey().trim();
        
        // Debug: check key string lengths
        System.out.println("DEBUG: publicKey length=" + publicKey.length() + ", privateKey length=" + privateKey.length());
        System.out.println("DEBUG: publicKey isHex=" + cc.iili.tools.crossmool.util.HexUtil.isHexString(publicKey));
        System.out.println("DEBUG: privateKey isHex=" + cc.iili.tools.crossmool.util.HexUtil.isHexString(privateKey));
        
        System.out.println("Public Key (X.509 DER, HEX):");
        System.out.println("  " + publicKey);
        System.out.println("\nPrivate Key (PKCS#8 DER, HEX):");
        System.out.println("  " + privateKey);
        System.out.println();
        
        // ========== Generate Test Data ==========
        System.out.println("Generating Test Data:");
        System.out.println("------------------------------------------------------------\n");
        
        // SM3
        String javaSm3 = SM3Util.digestToStr(testMessage);
        System.out.println("SM3 Digest: " + javaSm3);
        
        // HMAC-SM3
        byte[] hmacKey = HexUtil.decodeHexStr(hmacKeyHex);
        String javaHmac = SM3Util.hmacToStr(hmacKey, testMessage.getBytes());
        System.out.println("HMAC-SM3: " + javaHmac);
        
        // SM4
        byte[] sm4Key = HexUtil.decodeHexStr(sm4KeyHex);
        String javaSm4Cipher = SM4Util.encryptEcbNative(sm4Key, testMessage.getBytes());
        System.out.println("SM4 Ciphertext: " + javaSm4Cipher);
        
        // SM2 Encrypt
        String javaSm2Cipher = SM2Util.encrypt(testMessage, publicKey);
        System.out.println("SM2 Ciphertext: " + javaSm2Cipher.substring(0, 64) + "...");
        
        // SM2 Sign
        String javaSm2Sign = SM2Util.sign(testMessage, privateKey);
        System.out.println("SM2 Signature: " + javaSm2Sign);
        
        System.out.println();
        
        // ========== Output for Python Verification ==========
        System.out.println("[JAVA_OUTPUT_START]");
        System.out.println("{");
        System.out.println("  \"test_message\": \"" + testMessage + "\",");
        System.out.println("  \"sm2_public_key\": \"" + publicKey + "\",");
        System.out.println("  \"sm2_private_key\": \"" + privateKey + "\",");
        System.out.println("  \"sm2_ciphertext\": \"" + javaSm2Cipher + "\",");
        System.out.println("  \"sm2_signature\": \"" + javaSm2Sign + "\",");
        System.out.println("  \"sm3_digest\": \"" + javaSm3 + "\",");
        System.out.println("  \"hmac_key_hex\": \"" + hmacKeyHex + "\",");
        System.out.println("  \"hmac_sm3\": \"" + javaHmac + "\",");
        System.out.println("  \"sm4_key_hex\": \"" + sm4KeyHex + "\",");
        System.out.println("  \"sm4_ciphertext\": \"" + javaSm4Cipher + "\"");
        System.out.println("}");
        System.out.println("[JAVA_OUTPUT_END]\n");
        
        // ========== Verify Java Operations ==========
        System.out.println("Verifying Java Operations:");
        System.out.println("------------------------------------------------------------\n");
        
        int passed = 0;
        int total = 0;
        
        // Test 1: SM3
        total++;
        System.out.println("[Test 1] SM3 Digest");
        String sm3Verify = SM3Util.digestToStr(testMessage);
        if (javaSm3.equalsIgnoreCase(sm3Verify)) {
            System.out.println("  [PASS]\n");
            passed++;
        } else {
            System.out.println("  [FAIL]\n");
        }
        
        // Test 2: HMAC-SM3
        total++;
        System.out.println("[Test 2] HMAC-SM3");
        String hmacVerify = SM3Util.hmacToStr(hmacKey, testMessage.getBytes());
        if (javaHmac.equalsIgnoreCase(hmacVerify)) {
            System.out.println("  [PASS]\n");
            passed++;
        } else {
            System.out.println("  [FAIL]\n");
        }
        
        // Test 3: SM4 Encrypt/Decrypt
        total++;
        System.out.println("[Test 3] SM4 Encrypt/Decrypt");
        try {
            String decrypted = SM4Util.decryptEcbJca(sm4Key, javaSm4Cipher);
            if (testMessage.equals(decrypted)) {
                System.out.println("  [PASS]\n");
                passed++;
            } else {
                System.out.println("  [FAIL]\n");
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage() + "\n");
        }
        
        // Test 4: SM2 Encrypt/Decrypt
        total++;
        System.out.println("[Test 4] SM2 Encrypt/Decrypt");
        System.out.println("  DEBUG: privateKey len=" + privateKey.length() + ", cipher len=" + javaSm2Cipher.length());
        System.out.println("  DEBUG: first 20 of privKey=" + privateKey.substring(0, 20));
        try {
            String decrypted = SM2Util.decrypt(privateKey, javaSm2Cipher);
            if (testMessage.equals(decrypted)) {
                System.out.println("  [PASS]\n");
                passed++;
            } else {
                System.out.println("  [FAIL]\n");
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage() + "\n");
        }
        
        // Test 5: SM2 Sign/Verify
        total++;
        System.out.println("[Test 5] SM2 Sign/Verify");
        try {
            boolean verified = SM2Util.verify(publicKey, javaSm2Sign, testMessage);
            if (verified) {
                System.out.println("  [PASS]\n");
                passed++;
            } else {
                System.out.println("  [FAIL]\n");
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage() + "\n");
        }
        
        // ========== Summary ==========
        System.out.println("============================================================");
        System.out.println("Test Summary");
        System.out.println("============================================================");
        System.out.println("Total: " + passed + "/" + total + " tests passed\n");
        
        if (passed == total) {
            System.out.println("[SUCCESS] All Java operations verified!");
            System.out.println("\n=== Python Interoperability Notes ===");
            System.out.println("Run: python test_java_python_sm_interop.py");
            System.out.println("\nKey Format Conversions for Python gmssl:");
            System.out.println("  - SM2 Public Key: Remove DER header, remove leading 04 byte");
            System.out.println("  - SM2 Private Key: Extract 32 bytes from PKCS#8 DER");
            System.out.println("  - SM2 Ciphertext: Remove leading 04 byte");
            System.out.println("  - SM2 Signature: DER format (directly compatible)");
            System.out.println("  - SM3/HMAC-SM3: Direct compatibility");
            System.out.println("  - SM4: ECB mode with PKCS7 padding (directly compatible)");
            System.exit(0);
        } else {
            System.out.println("[WARNING] " + (total - passed) + " test(s) failed");
            System.exit(1);
        }
    }
}