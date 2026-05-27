import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

public class InteropTest {
    public static void main(String[] args) {
        // Python encrypted: key=ad1486d58d4e012d4c94936616ecf7d6
        String keyHex = "ad1486d58d4e012d4c94936616ecf7d6";
        byte[] key = SM4Util.parseHexKey(keyHex);
        String pythonEncrypted = "5Dz0GG14i4i5Z6CUpgM4DYLMjRcuxbVq2AdIXRbummh4eU8+6CK07NL2bKtEqdvh+Ku8WCdPasakJ5Uf2/s=";
        
        try {
            String decrypted = SM4Util.decryptGcmNativeToString(key, pythonEncrypted);
            System.out.println("Decrypted: " + decrypted);
            if (decrypted.equals("Hello, 這是国密SM4測試數據")) {
                System.out.println("[PASS] Python GCM -> Java Native decrypt");
            } else {
                System.out.println("[FAIL] Mismatch: " + decrypted);
            }
        } catch (Exception e) {
            System.out.println("[FAIL] Error: " + e.getMessage());
        }
        
        try {
            String decrypted2 = SM4Util.decryptGcmJca(key, pythonEncrypted);
            System.out.println("JCA Decrypted: " + decrypted2);
            if (decrypted2.equals("Hello, 這是国密SM4測試數據")) {
                System.out.println("[PASS] Python GCM -> Java JCA decrypt");
            } else {
                System.out.println("[FAIL] Mismatch: " + decrypted2);
            }
        } catch (Exception e) {
            System.out.println("[FAIL] Error: " + e.getMessage());
        }
    }
}
