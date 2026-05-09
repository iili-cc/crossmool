// No package declaration - run from testcase directory
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.util.HexUtil;
import cc.iili.tools.crossmool.util.SM2KeyUtil;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.*;

/**
 * Test SM2 decrypt and verify with fixed test data from test_data.json
 */
public class TestDecryptVerify {
    
    public static void main(String[] args) throws Exception {
        System.out.println("Test SM2 Decrypt and Verify");
        System.out.println("===========================\n");
        
        // Read test_data.json
        String jsonContent = Files.readString(Paths.get("test_data.json"));
        
        // Extract values using regex
        String privateKey = extractJsonValue(jsonContent, "sm2_private_key");
        String publicKey = extractJsonValue(jsonContent, "sm2_public_key");
        String ciphertext = extractJsonValue(jsonContent, "sm2_ciphertext");
        String signature = extractJsonValue(jsonContent, "sm2_signature");
        
        System.out.println("Loaded from test_data.json:");
        System.out.println("  Private key length: " + privateKey.length());
        System.out.println("  Public key length: " + publicKey.length());
        System.out.println("  Ciphertext length: " + ciphertext.length());
        System.out.println("  Signature length: " + signature.length());
        System.out.println();
        
        // Verify key formats
        System.out.println("Key format verification:");
        System.out.println("  Private key is HEX: " + HexUtil.isHexString(privateKey));
        System.out.println("  Public key is HEX: " + HexUtil.isHexString(publicKey));
        System.out.println("  Ciphertext is HEX: " + HexUtil.isHexString(ciphertext));
        System.out.println("  Signature is HEX: " + HexUtil.isHexString(signature));
        System.out.println();
        
        // Debug: print actual bytes
        System.out.println("Debug: Private key first 10 chars: [" + privateKey.substring(0, 10) + "]");
        System.out.println("Debug: Private key char at 0: " + (int)privateKey.charAt(0));
        System.out.println("Debug: Private key char at 1: " + (int)privateKey.charAt(1));
        
        // Debug: decode and check bytes
        byte[] privKeyBytes = SM2KeyUtil.convertStringToBytes(privateKey);
        System.out.println("Debug: Private key bytes length: " + privKeyBytes.length);
        System.out.println("Debug: Private key first 10 bytes: ");
        for (int i = 0; i < 10; i++) {
            System.out.print(String.format("%02X ", privKeyBytes[i]));
        }
        System.out.println();
        System.out.println("Debug: Private key last 10 bytes: ");
        for (int i = privKeyBytes.length - 10; i < privKeyBytes.length; i++) {
            System.out.print(String.format("%02X ", privKeyBytes[i]));
        }
        System.out.println();
        
        // Check DER structure
        System.out.println("Debug: DER structure:");
        System.out.println("  Tag: " + String.format("%02X", privKeyBytes[0]));
        System.out.println("  Length encoding: " + String.format("%02X", privKeyBytes[1]));
        if (privKeyBytes[1] == (byte)0x81) {
            int length = privKeyBytes[2] & 0xFF;  // Convert to unsigned
            System.out.println("  Long form 1 byte, length = " + length);
            System.out.println("  Content length = " + (privKeyBytes.length - 3));
            System.out.println("  Match = " + (length == privKeyBytes.length - 3));
        }
        System.out.println();
        
        // Test decrypt
        System.out.println("Test 1: SM2 Decrypt");
        try {
            String decrypted = SM2Util.decrypt(privateKey, ciphertext);
            System.out.println("  Decrypted: " + decrypted);
            System.out.println("  [PASS]\n");
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage());
            e.printStackTrace(System.out);
            System.out.println();
        }
        
        // Test verify
        System.out.println("Test 2: SM2 Verify");
        try {
            boolean verified = SM2Util.verify(publicKey, signature, "Hello, Cross-Language Interop Test!");
            System.out.println("  Verified: " + verified);
            if (verified) {
                System.out.println("  [PASS]\n");
            } else {
                System.out.println("  [FAIL] Signature verification failed\n");
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage());
            e.printStackTrace(System.out);
            System.out.println();
        }
        
        System.out.println("Test complete!");
    }
    
    private static String extractJsonValue(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        throw new RuntimeException("Key not found: " + key);
    }
}