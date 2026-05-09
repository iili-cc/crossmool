// No package declaration - run from testcase directory
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

/**
 * Test decrypt Python SM4 ciphertext with Java
 */
public class TestPythonSM4 {
    
    public static void main(String[] args) throws Exception {
        System.out.println("Test Python SM4 -> Java Decrypt");
        System.out.println("================================\n");
        
        // Test data from Python output
        String keyHex = "9bac79cd836f9ff36d795d9d96b3304f";
        String pythonCiphertext = "40e7984272876a52b4f3d2f89b14684c695fb9bbdebdd8c15ca03f44fcfdc7dc89dbc8bfacdabcf7348d866c8e1a0c64";
        String expectedMessage = "Hello, Cross-Language Interop Test!";
        
        System.out.println("Key: " + keyHex);
        System.out.println("Python ciphertext: " + pythonCiphertext);
        System.out.println("Expected message: " + expectedMessage);
        System.out.println();
        
        // Decrypt
        System.out.println("Decrypting with Java SM4Util.decryptEcbJca()...");
        String decrypted = SM4Util.decryptEcbJca(HexUtil.decodeHexStr(keyHex), pythonCiphertext);
        
        System.out.println("Decrypted: " + decrypted);
        System.out.println();
        
        // Verify
        if (expectedMessage.equals(decrypted)) {
            System.out.println("[PASS] Python->Java SM4 interop works!");
        } else {
            System.out.println("[FAIL] Message mismatch!");
            System.out.println("  Expected: " + expectedMessage);
            System.out.println("  Got: " + decrypted);
        }
        
        // Also test Java encrypt -> Python decrypt
        System.out.println("\n" + "=".repeat(40));
        System.out.println("Test Java Encrypt -> Python Decrypt");
        System.out.println("=".repeat(40) + "\n");
        
        System.out.println("Encrypting with Java...");
        String javaCiphertext = SM4Util.encryptEcbJca(HexUtil.decodeHexStr(keyHex), expectedMessage);
        System.out.println("Java ciphertext: " + javaCiphertext);
        System.out.println();
        
        System.out.println("Now run Python to decrypt this ciphertext:");
        System.out.println("  Key: " + keyHex);
        System.out.println("  Ciphertext: " + javaCiphertext);
    }
}