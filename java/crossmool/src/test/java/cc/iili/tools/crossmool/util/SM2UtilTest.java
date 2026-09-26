package cc.iili.tools.crossmool.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.constant.SM2Constant;
import cc.iili.tools.crossmool.tool.SM2Util;

@SuppressWarnings("deprecation")
class SM2UtilTest {

    @Test
    void testGenerateKeyPairBase64() {
        SerialKeyPair keyPairBase64 = SM2Util.generateKeyPairBase64();
        assertNotNull(keyPairBase64, "SerialKeyPairBase64 should not be null");
    }
    @Test
    void testGenerateKeyPairBHex() {
        SerialKeyPair keyPairHex = SM2Util.generateKeyPairHex();
        assertNotNull(keyPairHex, "SerialKeyPairHex should not be null");
    }

    @Test
    void testEncryptToBase64() {
        String publicKey = SM2Constant.CIPHER_PUBLIC_KEY_BASE64;
        String privateKey = SM2Constant.CIPHER_PRIVATE_KEY_BASE64;

        String base64 = SM2Util.encryptToBase64("Hello, 张三丰!", publicKey);
        String decrypted = SM2Util.decrypt(base64, privateKey);
        assertEquals("Hello, 张三丰!", decrypted, "Decrypted content should match the original");
    }

    @Test
    void testGenerateKeyPair() {
        SerialKeyPair keyPairBase64 = SM2Util.generateKeyPairBase64();
        SerialKeyPair keyPairHex = SM2Util.generateKeyPairHex();
        assertNotNull(keyPairBase64, "SerialKeyPairBase64 should not be null");
        assertNotNull(keyPairHex, "SerialKeyPairHex should not be null");
    }

    @Test
    void testEncryptSignToBase64() {
        String content = "Hello, 张三丰!";
        CiphertextSignaturePair pair = SM2Util.encryptSign(content, SM2Constant.CIPHER_PUBLIC_KEY_BASE64, SM2Constant.SIGN_PRIVATE_KEY_BASE64);
        String verifyDecrypt = SM2Util.verifyDecrypt(pair, SM2Constant.SIGN_PUBLIC_KEY_BASE64, SM2Constant.CIPHER_PRIVATE_KEY_BASE64);
        assertEquals(content, verifyDecrypt, "Decrypted content should match the original");
    }

    @Test
    void testSignVerifyWithCustomUserId() {
        SerialKeyPair keyPair = SM2Util.generateKeyPairHex();
        String privateKey = keyPair.getPrivateKey();
        String publicKey = keyPair.getPublicKey();
        String content = "Hello, custom SM2 user ID!";
        String customUserId = "410101199001011234";

        byte[] contentBytes = content.getBytes(StandardCharsets.UTF_8);
        byte[] privateKeyBytes = HexUtil.decodeHexStr(privateKey);
        byte[] publicKeyBytes = HexUtil.decodeHexStr(publicKey);
        byte[] userIdBytes = customUserId.getBytes(StandardCharsets.UTF_8);

        byte[] signature = SM2Util.sign(contentBytes, privateKeyBytes, userIdBytes);
        // Verification with the same userId should pass
        assertTrue(SM2Util.verify(contentBytes, publicKeyBytes, signature, userIdBytes));
        // Verification with the default userId should fail (userId mismatch)
        assertFalse(SM2Util.verify(contentBytes, publicKeyBytes, signature));
    }

}
