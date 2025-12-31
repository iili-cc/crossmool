package cc.iili.tools.crossmool.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.constant.SM2Constant;

class SM2UtilsTest {

    @Test
    void testGenerateKeyPairBase64() {
        SerialKeyPair keyPairBase64 = SM2Utils.generateKeyPairBase64();
        assertNotNull(keyPairBase64, "SerialKeyPairBase64 should not be null");
    }
    @Test
    void testGenerateKeyPairBHex() {
        SerialKeyPair keyPairHex = SM2Utils.generateKeyPairHex();
        assertNotNull(keyPairHex, "SerialKeyPairHex should not be null");
    }
    
    @Test
    void testEncryptToBase64() {
        String publicKey = SM2Constant.CIPHER_PUBLIC_KEY_BASE64;
        String privateKey = SM2Constant.CIPHER_PRIVATE_KEY_BASE64;
        
        String base64 = SM2Utils.encryptToBase64("Hello, 张三丰!", publicKey);
        System.out.println("-----------------------------------");
        System.out.println("Ciphertext (Base64): " + base64);
        String decrypted = SM2Utils.decrypt(base64, privateKey);
        System.out.println("Decrypted Content: " + decrypted);
        System.out.println("-----------------------------------");
        
        assertEquals("Hello, 张三丰!", decrypted, "Decrypted content should match the original");
        
    }
    
    @Test
    void generateKeyPair() {
        SerialKeyPair keyPairBase64 = SM2Utils.generateKeyPairBase64();
        System.out.println("Generated KeyPair (Base64):\n" + keyPairBase64);
        SerialKeyPair keyPairHex = SM2Utils.generateKeyPairHex();
        System.out.println("Generated KeyPair (Hex):\n" + keyPairHex);
        assertNotNull(keyPairBase64, "SerialKeyPairBase64 should not be null");
        assertNotNull(keyPairHex, "SerialKeyPairHex should not be null");
    }
    
    @Test
    void testEncryptSignToBase64() {
        String content = "Hello, 张三丰!";
        CiphertextSignaturePair pair = SM2Utils.encryptSign(content, SM2Constant.CIPHER_PUBLIC_KEY_BASE64, SM2Constant.SIGN_PRIVATE_KEY_BASE64);
        System.out.println("Ciphertext (Base64): " + pair.getCiphertext() + "\nSignature (Base64): " + pair.getSignature());
        String verifyDecrypt = SM2Utils.verifyDecrypt(pair, SM2Constant.SIGN_PUBLIC_KEY_BASE64, SM2Constant.CIPHER_PRIVATE_KEY_BASE64);
        System.out.println("Decrypted Content: " + verifyDecrypt);
        assertEquals(content, verifyDecrypt, "Decrypted content should match the original");
    }
    

}
