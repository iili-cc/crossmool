package cc.iili.tools.crossmool.util;

import org.junit.jupiter.api.Test;

class SM2UtilsTest {

    @Test
    void testGenerateKeyPairBase64() {
        SM2Utils.generateKeyPairBase64();
    }
    @Test
    void testGenerateKeyPairBHex() {
        SM2Utils.generateKeyPairHex();
    }
    
    @Test
    void testEncryptToBase64() {
        var keyPair = SM2Utils.generateKeyPairBase64();
        String publicKey = keyPair.getPublicKey();
        String data = "Hello, 张三丰!";
        String encryptedData = SM2Utils.encryptToBase64(data, publicKey);
        System.out.println("Encrypted Data (Base64): " + encryptedData);
    }

}
