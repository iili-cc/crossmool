// No package declaration - run from testcase directory
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.util.HexUtil;

/**
 * Direct SM2 test without any logging interference.
 */
public class DirectSM2Test {
    
    public static void main(String[] args) {
        System.out.println("Direct SM2 Test");
        System.out.println("===============\n");
        
        String testMessage = "Hello, Direct SM2 Test!";
        
        // Generate keypair
        SerialKeyPair keys = SM2Util.generateKeyPairHex();
        String publicKey = keys.getPublicKey();
        String privateKey = keys.getPrivateKey();
        
        // Verify key formats
        System.out.println("Key format verification:");
        System.out.println("  Public key length: " + publicKey.length());
        System.out.println("  Private key length: " + privateKey.length());
        System.out.println("  Public key is HEX: " + HexUtil.isHexString(publicKey));
        System.out.println("  Private key is HEX: " + HexUtil.isHexString(privateKey));
        System.out.println("  Public key starts with 30: " + publicKey.startsWith("30"));
        System.out.println("  Private key starts with 30: " + privateKey.startsWith("30"));
        System.out.println();
        
        // Test encrypt/decrypt
        System.out.println("Test 1: Encrypt/Decrypt");
        try {
            String ciphertext = SM2Util.encrypt(testMessage, publicKey);
            System.out.println("  Encrypted (first 64 chars): " + ciphertext.substring(0, 64) + "...");
            System.out.println("  Ciphertext is HEX: " + HexUtil.isHexString(ciphertext));
            
            String decrypted = SM2Util.decrypt(privateKey, ciphertext);
            System.out.println("  Decrypted: " + decrypted);
            
            if (testMessage.equals(decrypted)) {
                System.out.println("  [PASS] Encrypt/Decrypt works!\n");
            } else {
                System.out.println("  [FAIL] Message mismatch!\n");
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage() + "\n");
            e.printStackTrace(System.out);
        }
        
        // Test sign/verify
        System.out.println("Test 2: Sign/Verify");
        try {
            String signature = SM2Util.sign(testMessage, privateKey);
            System.out.println("  Signature (first 64 chars): " + signature.substring(0, 64) + "...");
            System.out.println("  Signature is HEX: " + HexUtil.isHexString(signature));
            
            boolean verified = SM2Util.verify(publicKey, signature, testMessage);
            System.out.println("  Verified: " + verified);
            
            if (verified) {
                System.out.println("  [PASS] Sign/Verify works!\n");
            } else {
                System.out.println("  [FAIL] Verification failed!\n");
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage() + "\n");
            e.printStackTrace(System.out);
        }
        
        System.out.println("Direct SM2 Test Complete!");
    }
}