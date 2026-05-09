// No package declaration - run from testcase directory
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;

/**
 * Simple SM2 test to verify encrypt/decrypt and sign/verify work correctly.
 */
public class SimpleSM2Test {
    
    public static void main(String[] args) {
        System.out.println("Simple SM2 Test");
        System.out.println("===============\n");
        
        String testMessage = "Hello, SM2 Test!";
        
        // Generate keypair
        SerialKeyPair keys = SM2Util.generateKeyPairHex();
        String publicKey = keys.getPublicKey();
        String privateKey = keys.getPrivateKey();
        
        System.out.println("Keys generated:");
        System.out.println("  Public:  " + publicKey.substring(0, 64) + "...");
        System.out.println("  Private: " + privateKey.substring(0, 64) + "...");
        System.out.println();
        
        // Test encrypt/decrypt
        System.out.println("Test 1: Encrypt/Decrypt");
        try {
            String ciphertext = SM2Util.encrypt(testMessage, publicKey);
            System.out.println("  Encrypted: " + ciphertext.substring(0, 64) + "...");
            
            String decrypted = SM2Util.decrypt(privateKey, ciphertext);
            System.out.println("  Decrypted: " + decrypted);
            
            if (testMessage.equals(decrypted)) {
                System.out.println("  [PASS] Encrypt/Decrypt works!\n");
            } else {
                System.out.println("  [FAIL] Message mismatch!\n");
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage() + "\n");
            e.printStackTrace();
        }
        
        // Test sign/verify
        System.out.println("Test 2: Sign/Verify");
        try {
            String signature = SM2Util.sign(testMessage, privateKey);
            System.out.println("  Signature: " + signature);
            
            boolean verified = SM2Util.verify(publicKey, signature, testMessage);
            System.out.println("  Verified: " + verified);
            
            if (verified) {
                System.out.println("  [PASS] Sign/Verify works!\n");
            } else {
                System.out.println("  [FAIL] Verification failed!\n");
            }
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage() + "\n");
            e.printStackTrace();
        }
        
        System.out.println("Simple SM2 Test Complete!");
    }
}