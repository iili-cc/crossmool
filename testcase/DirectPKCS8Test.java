// No package declaration - run from testcase directory
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.util.encoders.Hex;

/**
 * Direct PKCS#8 test
 */
public class DirectPKCS8Test {
    
    public static void main(String[] args) throws Exception {
        System.out.println("Direct PKCS#8 Test");
        System.out.println("==================\n");
        
        // First trigger SM2Util static initializer to register BC provider
        System.out.println("Loading SM2Util to register BC provider...");
        cc.iili.tools.crossmool.tool.SM2Util.generateKeyPairHex();
        System.out.println("BC provider registered.\n");
        
        // Use the private key from GenerateAndTest output
        String privateKeyHex = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042064bb3a57ebc4aec12e1afe8c904b4f44d4b1ff051aca41165bdd072b0d117ce2a00a06082a811ccf5501822da14403420004ef2b4fe6f35f2a59ff01c6a90bea5e058d51164545678e8057369879f024aa1b23fa57beb6e1372dccb2d19092834b2a8431c5092f710ec204be565a7da31603";
        
        byte[] privBytes = Hex.decode(privateKeyHex);
        System.out.println("Private key bytes length: " + privBytes.length);
        
        // Test 1: Direct parsing with BC provider
        System.out.println("\nTest 1: Direct PKCS#8 with BC provider");
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privBytes);
            KeyFactory kf = KeyFactory.getInstance("EC", "BC");
            PrivateKey pk = kf.generatePrivate(keySpec);
            System.out.println("  [OK] Success!");
            System.out.println("  Key algorithm: " + pk.getAlgorithm());
            System.out.println("  Key format: " + pk.getFormat());
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage());
            e.printStackTrace(System.out);
        }
        
        // Test 2: Direct parsing without provider
        System.out.println("\nTest 2: Direct PKCS#8 without provider");
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PrivateKey pk = kf.generatePrivate(keySpec);
            System.out.println("  [OK] Success!");
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage());
        }
        
        // Test 3: SM2KeyUtil.convertPKCS8BytesToPrivateKey
        System.out.println("\nTest 3: SM2KeyUtil.convertPKCS8BytesToPrivateKey");
        try {
            cc.iili.tools.crossmool.util.SM2KeyUtil.convertPKCS8BytesToPrivateKey(privBytes);
            System.out.println("  [OK] Success!");
        } catch (Exception e) {
            System.out.println("  [FAIL] " + e.getMessage());
            e.printStackTrace(System.out);
        }
        
        System.out.println("\nTest complete!");
    }
}