// No package declaration - run from testcase directory
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;

/**
 * Generate keys and immediately test decrypt/sign/verify - no JSON serialization
 */
public class GenerateAndTest {
    
    public static void main(String[] args) throws Exception {
        System.out.println("Generate and Test SM2");
        System.out.println("=====================\n");
        
        String testMessage = "Hello, Generate and Test!";
        
        // Generate keypair
        SerialKeyPair keys = SM2Util.generateKeyPairHex();
        String publicKey = keys.getPublicKey();
        String privateKey = keys.getPrivateKey();
        
        System.out.println("Keys generated:");
        System.out.println("  Public key length: " + publicKey.length());
        System.out.println("  Private key length: " + privateKey.length());
        System.out.println();
        
        // Encrypt
        System.out.println("Encrypting...");
        String ciphertext = SM2Util.encrypt(testMessage, publicKey);
        System.out.println("  Ciphertext length: " + ciphertext.length());
        System.out.println();
        
        // Decrypt
        System.out.println("Decrypting...");
        String decrypted = SM2Util.decrypt(ciphertext, privateKey);
        System.out.println("  Decrypted: " + decrypted);
        if (testMessage.equals(decrypted)) {
            System.out.println("  [PASS] Decrypt works!\n");
        } else {
            System.out.println("  [FAIL] Message mismatch!\n");
        }
        
        // Sign
        System.out.println("Signing...");
        String signature = SM2Util.sign(testMessage, privateKey);
        System.out.println("  Signature length: " + signature.length());
        System.out.println();
        
        // Verify
        System.out.println("Verifying...");
        boolean verified = SM2Util.verify(testMessage, publicKey, signature);
        System.out.println("  Verified: " + verified);
        if (verified) {
            System.out.println("  [PASS] Verify works!\n");
        } else {
            System.out.println("  [FAIL] Verification failed!\n");
        }
        
        System.out.println("Test complete!");
    }
}