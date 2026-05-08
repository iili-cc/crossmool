package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;

/**
 * 最终诊断测试：
 * 1. Java 自签自验
 * 2. 用 C 生成的密钥（raw format）签一条消息，让 Java 验
 * 3. 用 C 签一条消息，Java 验证
 */
public class FinalDiagTest {
    public static void main(String[] args) {
        String pubKeyX509 = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        String privKeyPKCS8 = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";

        String message = "Hello, Crossmool!";

        // Test 1: Java self sign/verify
        System.out.println("=== Test 1: Java self sign/verify ===");
        String javaSig = SM2Util.sign(message, privKeyPKCS8, false);
        System.out.println("Java signature: " + javaSig);
        boolean ok = SM2Util.verify(message, pubKeyX509, javaSig);
        System.out.println("Java self verify: " + (ok ? "PASS" : "FAIL"));

        // Test 2: Verify C signature
        // C signed with raw privkey "72e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057"
        // C signature: 304402202f617c8de652fa04f1118d5a70cf8b10482becbfd3d8a7410c1310f5d684795902202598743a06905a7db220d9050ddf423b66c60d934eb5e43b220f674d92859150
        System.out.println("\n=== Test 2: Java verify C signature ===");
        String cSig = "304402202f617c8de652fa04f1118d5a70cf8b10482becbfd3d8a7410c1310f5d684795902202598743a06905a7db220d9050ddf423b66c60d934eb5e43b220f674d92859150";
        boolean cOk = SM2Util.verify(message, pubKeyX509, cSig);
        System.out.println("Java verify C sig: " + (cOk ? "PASS" : "FAIL"));

        // Test 3: C 签 ciphertext, Java verify
        // C CT sig: 3045022043078444366246b8d49b4d9e30e993b53f8f8ee5a122f9675e85996768397a6502210089320ec14cd5e5ff126736360a87e663f997818bf3b30950d1e1c9db2400c1ca
        System.out.println("\n=== Test 3: Java verify C CT signature ===");
        String ctMsg = "046a2146cffa0e592b74f49304a75eb73449be5ae5f7cabac4a3938ae34539207472a2b912701a096ad7182772cede4439cc0642c3b56d123ca9c8b11b569ab94197d41b436a9240ef89ed76d01bee13129c5abc6aefa0d262424f147382f478fae20b93b2b671f0a33eec6a00830f44a191";
        String cCtSig = "3045022043078444366246b8d49b4d9e30e993b53f8f8ee5a122f9675e85996768397a6502210089320ec14cd5e5ff126736360a87e663f997818bf3b30950d1e1c9db2400c1ca";
        boolean cCtOk = SM2Util.verify(ctMsg, pubKeyX509, cCtSig);
        System.out.println("Java verify C CT sig: " + (cCtOk ? "PASS" : "FAIL"));

        // Test 4: Java sign "Hello, Crossmool!", output for C to verify
        // (this is what we already did in CrossVerifyTest)

        // Test 5: Check if SM2Util.encryptSign uses the correct keys
        // keys.json has: encryption_public_key = signature_public_key = same
        // sign_private_key = encryption_private_key = same
        // So sign uses the same keypair as encrypt - this is correct
        System.out.println("\n=== Test 5: Java encryptSign ===");
        try {
            cc.iili.tools.crossmool.bean.CiphertextSignaturePair pair =
                SM2Util.encryptSign(message, pubKeyX509, privKeyPKCS8, false);
            System.out.println("Encrypted: " + pair.getCiphertext());
            System.out.println("Signature: " + pair.getSignature());

            // Verify the signature
            boolean encSignOk = SM2Util.verify(pair.getCiphertext(), pubKeyX509, pair.getSignature());
            System.out.println("Verify encryptSign sig: " + (encSignOk ? "PASS" : "FAIL"));

            // Decrypt
            String decrypted = SM2Util.decrypt(pair.getCiphertext(), privKeyPKCS8);
            System.out.println("Decrypted: " + decrypted);
            System.out.println("Decrypt match: " + decrypted.equals(message));
        } catch (Exception e) {
            System.out.println("encryptSign ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
