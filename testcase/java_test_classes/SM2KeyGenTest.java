package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.SerialKeyPair;

public class SM2KeyGenTest {
    public static void main(String[] args) {
        try {
            SerialKeyPair keyPair = SM2Util.generateKeyPairHex();
            // 输出纯密钥数据到 stdout，每行一个
            System.out.println(keyPair.getPublicKey());
            System.out.println(keyPair.getPrivateKey());
        } catch (Exception e) {
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
