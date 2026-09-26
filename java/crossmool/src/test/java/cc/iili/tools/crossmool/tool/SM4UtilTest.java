package cc.iili.tools.crossmool.tool;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import cc.iili.tools.crossmool.util.HexUtil;

class SM4UtilTest {

    private static final String PLAIN_TEXT = "Hello, 這是国密SM4測試數據";
    private static final byte[] FIXED_KEY = HexUtil.decodeHexStr("0123456789abcdeffedcba9876543210");
    private static final byte[] FIXED_IV = new byte[12]; // 00 01 02 ... 0b

    static {
        for (int i = 0; i < FIXED_IV.length; i++) {
            FIXED_IV[i] = (byte) i;
        }
    }

    @Test
    void testGenerateKey() {
        byte[] key = SM4Util.generateKey();
        assertEquals(16, key.length);
        assertEquals(32, SM4Util.generateKeyAsHex().length());
        assertEquals(24, SM4Util.generateKeyAsBase64().length());
    }

    @Test
    void testEncryptDecryptHex() {
        byte[] plainBytes = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        String cipherHex = SM4Util.encrypt(plainBytes, FIXED_KEY, false);
        byte[] decrypted = SM4Util.decryptToBytes(cipherHex, FIXED_KEY);
        assertArrayEquals(plainBytes, decrypted);
    }

    @Test
    void testEncryptDecryptBase64() {
        byte[] plainBytes = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);
        String cipherB64 = SM4Util.encrypt(plainBytes, FIXED_KEY, true);
        String decrypted = SM4Util.decrypt(cipherB64, FIXED_KEY);
        assertEquals(PLAIN_TEXT, decrypted);
    }

    @Test
    void testEncryptDecryptStringKey() {
        String hexKey = SM4Util.generateKeyAsHex();
        String cipherHex = SM4Util.encrypt(PLAIN_TEXT, hexKey);
        String decrypted = SM4Util.decrypt(cipherHex, hexKey);
        assertEquals(PLAIN_TEXT, decrypted);
    }

    @Test
    void testGcmNativeAndJcaConsistent() {
        String nativeCipher = SM4Util.encryptGcmNative(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8), FIXED_KEY, FIXED_IV);
        String jcaCipher = SM4Util.encryptGcmJca(PLAIN_TEXT, FIXED_KEY, FIXED_IV);
        // With the same key + IV, Native and JCA ciphertexts must be identical
        assertEquals(nativeCipher, jcaCipher);
        String decrypted = SM4Util.decryptGcmNativeToString(nativeCipher, FIXED_KEY);
        assertEquals(PLAIN_TEXT, decrypted);
    }

    @Test
    void testGcmDecryptHexInput() {
        // encrypt(..., false) produces Hex; decryptGcmNative should now also be able to decrypt it (issue #7 fix)
        String cipherHex = SM4Util.encrypt(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8), FIXED_KEY, false);
        String decrypted = SM4Util.decryptGcmNativeToString(cipherHex, FIXED_KEY);
        assertEquals(PLAIN_TEXT, decrypted);
    }

    @Test
    void testGcmAntiTampering() {
        String cipherHex = SM4Util.encrypt(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8), FIXED_KEY, false);
        // Tamper with one hex character in the middle of the ciphertext (keeping valid hex); GCM auth should fail
        char[] chars = cipherHex.toCharArray();
        chars[20] = (chars[20] == 'a') ? 'b' : 'a';
        String tampered = new String(chars);
        assertThrows(RuntimeException.class, () -> SM4Util.decryptToBytes(tampered, FIXED_KEY));
    }

}
