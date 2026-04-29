package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

public class SM2InteropTest {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: SM2InteropTest <content> <encPublicKey> <signPrivateKey>");
            System.exit(1);
        }
        
        String content = args[0];
        String encPublicKey = args[1];
        String signPrivateKey = args[2];
        
        try {
            CiphertextSignaturePair result = SM2Util.encryptSign(content, encPublicKey, signPrivateKey, false);
            System.out.println(result.getCiphertext() + "\t" + result.getSignature());
        } catch (Exception e) {
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
