package cc.iili.tools.crossmool.interop;

import cc.iili.tools.crossmool.tool.SM4Util;

/**
 * Python -> Java interoperability verification: verify that the SM4-GCM ciphertext generated
 * by Python can be correctly decrypted by Java.
 * Manual run: java -cp target/test-classes:target/classes:&lt;bcprov.jar&gt; cc.iili.tools.crossmool.interop.PythonInteropTest
 */
public class PythonInteropTest {

    public static void main(String[] args) {
        // Python encrypted: key=ad1486d58d4e012d4c94936616ecf7d6
        String keyHex = "ad1486d58d4e012d4c94936616ecf7d6";
        byte[] key = SM4Util.parseHexKey(keyHex);
        String pythonEncrypted = "5Dz0GG14i4i5Z6CUpgM4DYLMjRcuxbVq2AdIXRbummh4eU8+6CK07NL2bKtEqdvh+Ku8WCdPasakJ5Uf2/s=";

        try {
            String decrypted = SM4Util.decryptGcmNativeToString(pythonEncrypted, key);
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
            String decrypted2 = SM4Util.decryptGcmJca(pythonEncrypted, key);
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
