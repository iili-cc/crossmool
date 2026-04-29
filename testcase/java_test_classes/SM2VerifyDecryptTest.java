package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;

public class SM2VerifyDecryptTest {
    public static void main(String[] args) {
        if (args.length != 4) {
            System.err.println("Usage: SM2VerifyDecryptTest <ciphertext> <signature> <signPublicKey> <decPrivateKey>");
            System.exit(1);
        }
        
        String ciphertext = args[0];
        String signature = args[1];
        String signPublicKey = args[2];
        String decPrivateKey = args[3];
        
        try {
            String decrypted = SM2Util.verifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey);
            System.out.println("SUCCESS:" + decrypted);
        } catch (Exception e) {
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}