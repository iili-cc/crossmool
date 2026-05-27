import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

public class JavaVerifyTest {
    public static void main(String[] args) throws Exception {
        String signPubKeyHex = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        String signPrivKeyHex = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        String encPrivKeyHex = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        String encPubKeyHex = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        
        String ctHex = "046a2146cffa0e592b74f49304a75eb73449be5ae5f7cabac4a3938ae34539207472a2b912701a096ad7182772cede4439cc0642c3b56d123ca9c8b11b569ab94197d41b436a9240ef89ed76d01bee13129c5abc6aefa0d262424f147382f478fae20b93b2b671f0a33eec6a00830f44a191";
        String sigHex = "3045022100c75cb782f822a99281d280bce9af156265252b60f1e28b74f34d1e4361c298a80220148a04be093709891f64484eb657fd54b1eab5c20c933b8133bdebe7dea4880f";
        String plaintext = "Hello, Crossmool!";
        
        // Test 1: Java verify Java's own signature
        boolean v1 = SM2Util.verify(ctHex, signPubKeyHex, sigHex);
        System.out.println("Java verify own signature: " + v1);
        
        // Test 2: Java sign the same ciphertext, then verify
        String newSig = SM2Util.sign(ctHex, signPrivKeyHex);
        System.out.println("New signature: " + newSig);
        boolean v2 = SM2Util.verify(ctHex, signPubKeyHex, newSig);
        System.out.println("Java sign+verify same ciphertext: " + v2);
        
        // Test 3: Java verifyDecrypt
        try {
            String decrypted = SM2Util.verifyDecrypt(ctHex, sigHex, signPubKeyHex, encPrivKeyHex);
            System.out.println("Java verifyDecrypt: " + decrypted);
        } catch (Exception e) {
            System.out.println("Java verifyDecrypt failed: " + e.getMessage());
        }
        
        // Test 4: Java encryptSign, then verifyDecrypt
        CiphertextSignaturePair pair = SM2Util.encryptSign(plaintext, encPubKeyHex, signPrivKeyHex);
        System.out.println("\nNew encryptSign:");
        System.out.println("  ciphertext: " + pair.getCiphertext().substring(0, Math.min(40, pair.getCiphertext().length())) + "...");
        System.out.println("  signature: " + pair.getSignature().substring(0, Math.min(40, pair.getSignature().length())) + "...");
        
        boolean v3 = SM2Util.verify(pair.getCiphertext(), signPubKeyHex, pair.getSignature());
        System.out.println("  verify new signature: " + v3);
        
        String dec = SM2Util.decrypt(pair.getCiphertext(), encPrivKeyHex);
        System.out.println("  decrypt: " + dec);
        
        // Test 5: Verify the stored signature against the stored ciphertext
        System.out.println("\nStored data verification:");
        System.out.println("  ctHex length: " + ctHex.length());
        System.out.println("  sigHex length: " + sigHex.length());
        System.out.println("  sig first bytes: " + sigHex.substring(0, 8));
        
        // Test 6: Sign the same ciphertext again - should be deterministic (no random)
        String sig2 = SM2Util.sign(ctHex, signPrivKeyHex);
        System.out.println("  sig again: " + sig2);
        System.out.println("  same sig: " + sig2.equals(sigHex));
    }
}
