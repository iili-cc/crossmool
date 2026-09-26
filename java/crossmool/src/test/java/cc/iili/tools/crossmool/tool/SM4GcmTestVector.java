package cc.iili.tools.crossmool.tool;

import java.nio.charset.StandardCharsets;

import cc.iili.tools.crossmool.util.HexUtil;

/**
 * Generate SM4-GCM test vectors for cross-language interoperability testing.
 * Run this class to produce fixed test vectors that other languages can verify against.
 */
public class SM4GcmTestVector {

    public static void main(String[] args) {
        // Fixed test key
        byte[] key = HexUtil.decodeHexStr("0123456789abcdeffedcba9876543210");
        // Fixed IV
        byte[] iv = new byte[12];
        for (int i = 0; i < 12; i++) iv[i] = (byte) i;
        // Test plaintext
        String plainText = "Hello, 這是国密SM4測試數據";

        // Encrypt with Native API
        String encryptedNative = SM4Util.encryptGcmNative(plainText.getBytes(StandardCharsets.UTF_8), key, iv);
        // Encrypt with JCA API
        String encryptedJca = SM4Util.encryptGcmJca(plainText, key, iv);

        System.out.println("=== SM4-GCM Test Vector ===");
        System.out.println("Key (Hex):     " + HexUtil.encodeHexStr(key));
        System.out.println("IV (Hex):      " + HexUtil.encodeHexStr(iv));
        System.out.println("Plaintext:     " + plainText);
        System.out.println("Native Base64: " + encryptedNative);
        System.out.println("JCA Base64:    " + encryptedJca);
        System.out.println("Native == JCA: " + encryptedNative.equals(encryptedJca));

        // Verify decryption
        String decrypted = SM4Util.decryptGcmNativeToString(encryptedNative, key);
        System.out.println("Decrypted:     " + decrypted);
        System.out.println("Match:         " + plainText.equals(decrypted));
    }
}
