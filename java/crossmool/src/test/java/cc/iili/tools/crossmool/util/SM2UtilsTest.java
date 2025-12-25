package cc.iili.tools.crossmool.util;

import org.junit.jupiter.api.Test;

import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.constant.SM2Constant;

class SM2UtilsTest {

//    @Test
//    void testGenerateKeyPairBase64() {
//        SM2Utils.generateKeyPairBase64();
//    }
//    @Test
//    void testGenerateKeyPairBHex() {
//        SM2Utils.generateKeyPairHex();
//    }
//    
//    @Test
//    void testEncryptToBase64() {
//        var keyPair = SM2Utils.generateKeyPairBase64();
//        String publicKey = keyPair.getPublicKey();
//        String data = "Hello, 张三丰!";
//        String encryptedData = SM2Utils.encryptToBase64(data, publicKey);
//        System.out.println("Encrypted Data (Base64): " + encryptedData);
//    }
//    
//    @Test
//    void generateKeyPair() {
//        SerialKeyPair keyPairBase64 = SM2Utils.generateKeyPairBase64();
//        System.out.println("Generated KeyPair (Base64):\n" + keyPairBase64);
//        SerialKeyPair keyPairHex = SM2Utils.generateKeyPairHex();
//        System.out.println("Generated KeyPair (Hex):\n" + keyPairHex);
//    }
    
    @Test
    void testEncryptSignToBase64() {
        String content = "Hello, 张三丰!";
        CiphertextSignaturePair pair = SM2Utils.encryptSign(content, SM2Constant.CIPHER_PUBLIC_KEY_BASE64, SM2Constant.SIGN_PRIVATE_KEY_BASE64);
        System.out.println("Ciphertext (Base64): " + pair.getCiphertext() + "\nSignature (Base64): " + pair.getSignature());
        String verifyDecrypt = SM2Utils.verifyDecrypt(pair, SM2Constant.SIGN_PUBLIC_KEY_BASE64, SM2Constant.CIPHER_PRIVATE_KEY_BASE64);
        System.out.println("Decrypted Content: " + verifyDecrypt);
        
    }
    

}
