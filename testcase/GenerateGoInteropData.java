import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.io.FileWriter;
import java.io.IOException;

/**
 * Java-Go SM2/SM3/SM4 Interoperability Test - Test Data Generator
 * Generates test data in both Hex and Base64 encoding for Go verification.
 */
public class GenerateGoInteropData {

    private static final String TEST_MESSAGE = "Hello, Java-Go Interop Test!";

    // Fixed SM4-GCM IV for deterministic output (12 bytes)
    private static final byte[] FIXED_SM4_IV = hexToBytes("0102030405060708090a0b0c");

    public static void main(String[] args) throws Exception {
        System.out.println("=== Java-Go SM Interop Test Data Generator ===\n");

        StringBuilder json = new StringBuilder();
        json.append("{\n");

        // ========================================
        // SM2 Section
        // ========================================
        System.out.println("--- SM2 ---");

        // Generate SM2 keypair (Hex)
        SerialKeyPair sm2KeysHex = SM2Util.generateKeyPairHex();
        String sm2PubKeyHex = sm2KeysHex.getPublicKey();
        String sm2PrivKeyHex = sm2KeysHex.getPrivateKey();
        System.out.println("SM2 PublicKey (Hex):  " + sm2PubKeyHex);
        System.out.println("SM2 PrivateKey (Hex): " + sm2PrivKeyHex);

        // Generate SM2 keypair (Base64)
        SerialKeyPair sm2KeysBase64 = SM2Util.generateKeyPairBase64();
        String sm2PubKeyBase64 = sm2KeysBase64.getPublicKey();
        String sm2PrivKeyBase64 = sm2KeysBase64.getPrivateKey();
        System.out.println("SM2 PublicKey (Base64):  " + sm2PubKeyBase64);
        System.out.println("SM2 PrivateKey (Base64): " + sm2PrivKeyBase64);

        // SM2 Encrypt (Hex)
        String sm2CiphertextHex = SM2Util.encrypt(TEST_MESSAGE, sm2PubKeyHex, false);
        System.out.println("SM2 Ciphertext (Hex): " + sm2CiphertextHex);

        // SM2 Encrypt (Base64)
        String sm2CiphertextBase64 = SM2Util.encrypt(TEST_MESSAGE, sm2PubKeyBase64, true);
        System.out.println("SM2 Ciphertext (Base64): " + sm2CiphertextBase64);

        // Verify SM2 decrypt works
        String decryptedHex = SM2Util.decrypt(sm2CiphertextHex, sm2PrivKeyHex);
        String decryptedBase64 = SM2Util.decrypt(sm2CiphertextBase64, sm2PrivKeyBase64);
        System.out.println("SM2 Decrypt verify (Hex):    " + TEST_MESSAGE.equals(decryptedHex));
        System.out.println("SM2 Decrypt verify (Base64): " + TEST_MESSAGE.equals(decryptedBase64));

        // SM2 Sign (Hex)
        String sm2SignatureHex = SM2Util.sign(TEST_MESSAGE, sm2PrivKeyHex, false);
        System.out.println("SM2 Signature (Hex): " + sm2SignatureHex);

        // SM2 Sign (Base64)
        String sm2SignatureBase64 = SM2Util.sign(TEST_MESSAGE, sm2PrivKeyBase64, true);
        System.out.println("SM2 Signature (Base64): " + sm2SignatureBase64);

        // Verify SM2 signature
        boolean verifyHex = SM2Util.verify(TEST_MESSAGE, sm2PubKeyHex, sm2SignatureHex);
        boolean verifyBase64 = SM2Util.verify(TEST_MESSAGE, sm2PubKeyBase64, sm2SignatureBase64);
        System.out.println("SM2 Verify (Hex):    " + verifyHex);
        System.out.println("SM2 Verify (Base64): " + verifyBase64);

        // SM2 EncryptSign (Hex) - encrypt with encPublicKey, sign ciphertext with signPrivateKey
        CiphertextSignaturePair encSignHex = SM2Util.encryptSign(TEST_MESSAGE, sm2PubKeyHex, sm2PrivKeyHex, false);
        System.out.println("SM2 EncryptSign Ciphertext (Hex): " + encSignHex.getCiphertext());
        System.out.println("SM2 EncryptSign Signature (Hex):  " + encSignHex.getSignature());

        // SM2 EncryptSign (Base64)
        CiphertextSignaturePair encSignBase64 = SM2Util.encryptSign(TEST_MESSAGE, sm2PubKeyBase64, sm2PrivKeyBase64, true);
        System.out.println("SM2 EncryptSign Ciphertext (Base64): " + encSignBase64.getCiphertext());
        System.out.println("SM2 EncryptSign Signature (Base64):  " + encSignBase64.getSignature());

        // Verify EncryptSign
        String verifyDecHex = SM2Util.verifyDecrypt(encSignHex, sm2PubKeyHex, sm2PrivKeyHex);
        String verifyDecBase64 = SM2Util.verifyDecrypt(encSignBase64, sm2PubKeyBase64, sm2PrivKeyBase64);
        System.out.println("SM2 VerifyDecrypt (Hex):    " + TEST_MESSAGE.equals(verifyDecHex));
        System.out.println("SM2 VerifyDecrypt (Base64): " + TEST_MESSAGE.equals(verifyDecBase64));

        // ========================================
        // SM3 Section
        // ========================================
        System.out.println("\n--- SM3 ---");

        // SM3 Digest (Hex)
        String sm3DigestHex = SM3Util.digestToStr(TEST_MESSAGE, false);
        System.out.println("SM3 Digest (Hex): " + sm3DigestHex);

        // SM3 Digest (Base64)
        String sm3DigestBase64 = SM3Util.digestToStr(TEST_MESSAGE, true);
        System.out.println("SM3 Digest (Base64): " + sm3DigestBase64);

        // HMAC-SM3 key (Hex, 32 bytes)
        String hmacKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        // HMAC-SM3 key (Base64)
        String hmacKeyBase64 = Base64.getEncoder().encodeToString(HexUtil.decodeHexStr(hmacKeyHex));

        // HMAC-SM3 (Hex key, Hex output)
        String hmacSm3Hex = SM3Util.hmacToStr(hmacKeyHex, TEST_MESSAGE, false);
        System.out.println("HMAC-SM3 (Hex): " + hmacSm3Hex);

        // HMAC-SM3 (Base64 key, Base64 output)
        String hmacSm3Base64 = SM3Util.hmacToStr(hmacKeyBase64, TEST_MESSAGE, true);
        System.out.println("HMAC-SM3 (Base64): " + hmacSm3Base64);

        // ========================================
        // SM4 Section
        // ========================================
        System.out.println("\n--- SM4-GCM ---");

        // Generate SM4 key
        String sm4KeyHex = SM4Util.generateKeyAsHex();
        byte[] sm4KeyBytes = HexUtil.decodeHexStr(sm4KeyHex);
        String sm4KeyBase64 = Base64.getEncoder().encodeToString(sm4KeyBytes);
        System.out.println("SM4 Key (Hex): " + sm4KeyHex);
        System.out.println("SM4 Key (Base64): " + sm4KeyBase64);

        // SM4-GCM encrypt with fixed IV using Native API (Base64 output)
        byte[] plainBytes = TEST_MESSAGE.getBytes(StandardCharsets.UTF_8);
        String sm4GcmBase64 = SM4Util.encryptGcmNative(sm4KeyBytes, plainBytes, FIXED_SM4_IV);
        System.out.println("SM4-GCM Ciphertext (Base64, IV+ciphertext+Tag): " + sm4GcmBase64);

        // Convert Base64 to Hex for Go verification
        byte[] sm4GcmRawBytes = Base64.getDecoder().decode(sm4GcmBase64);
        String sm4GcmHex = HexUtil.encodeHexStr(sm4GcmRawBytes);
        System.out.println("SM4-GCM Ciphertext (Hex, IV+ciphertext+Tag): " + sm4GcmHex);

        // Extract IV, ciphertext+Tag separately for clarity
        byte[] iv = new byte[12];
        byte[] cipherWithTag = new byte[sm4GcmRawBytes.length - 12];
        System.arraycopy(sm4GcmRawBytes, 0, iv, 0, 12);
        System.arraycopy(sm4GcmRawBytes, 12, cipherWithTag, 0, cipherWithTag.length);
        String sm4IvHex = HexUtil.encodeHexStr(iv);
        String sm4CipherTagHex = HexUtil.encodeHexStr(cipherWithTag);
        System.out.println("SM4-GCM IV (Hex):              " + sm4IvHex);
        System.out.println("SM4-GCM Ciphertext+Tag (Hex):  " + sm4CipherTagHex);

        // Verify SM4-GCM decrypt
        String sm4Decrypted = SM4Util.decryptGcmNativeToString(sm4KeyBytes, sm4GcmBase64);
        System.out.println("SM4-GCM Decrypt verify: " + TEST_MESSAGE.equals(sm4Decrypted));

        // Also test with JCA API for cross-verification
        String sm4GcmJcaBase64 = SM4Util.encryptGcmJca(sm4KeyBytes, TEST_MESSAGE, FIXED_SM4_IV);
        String sm4GcmJcaDecrypted = SM4Util.decryptGcmJca(sm4KeyBytes, sm4GcmJcaBase64);
        System.out.println("SM4-GCM JCA Decrypt verify: " + TEST_MESSAGE.equals(sm4GcmJcaDecrypted));

        // ========================================
        // Build JSON output
        // ========================================
        json.append("  \"test_message\": \"").append(escapeJson(TEST_MESSAGE)).append("\",\n");

        // SM2 keys
        json.append("  \"sm2\": {\n");
        json.append("    \"public_key_hex\": \"").append(sm2PubKeyHex).append("\",\n");
        json.append("    \"private_key_hex\": \"").append(sm2PrivKeyHex).append("\",\n");
        json.append("    \"public_key_base64\": \"").append(sm2PubKeyBase64).append("\",\n");
        json.append("    \"private_key_base64\": \"").append(sm2PrivKeyBase64).append("\",\n");

        // SM2 encrypt
        json.append("    \"ciphertext_hex\": \"").append(sm2CiphertextHex).append("\",\n");
        json.append("    \"ciphertext_base64\": \"").append(sm2CiphertextBase64).append("\",\n");

        // SM2 sign
        json.append("    \"signature_hex\": \"").append(sm2SignatureHex).append("\",\n");
        json.append("    \"signature_base64\": \"").append(sm2SignatureBase64).append("\",\n");

        // SM2 encryptSign
        json.append("    \"encrypt_sign\": {\n");
        json.append("      \"hex\": {\n");
        json.append("        \"ciphertext\": \"").append(escapeJson(encSignHex.getCiphertext())).append("\",\n");
        json.append("        \"signature\": \"").append(escapeJson(encSignHex.getSignature())).append("\"\n");
        json.append("      },\n");
        json.append("      \"base64\": {\n");
        json.append("        \"ciphertext\": \"").append(escapeJson(encSignBase64.getCiphertext())).append("\",\n");
        json.append("        \"signature\": \"").append(escapeJson(encSignBase64.getSignature())).append("\"\n");
        json.append("      }\n");
        json.append("    }\n");
        json.append("  },\n");

        // SM3
        json.append("  \"sm3\": {\n");
        json.append("    \"digest_hex\": \"").append(escapeJson(sm3DigestHex)).append("\",\n");
        json.append("    \"digest_base64\": \"").append(escapeJson(sm3DigestBase64)).append("\",\n");
        json.append("    \"hmac_key_hex\": \"").append(escapeJson(hmacKeyHex)).append("\",\n");
        json.append("    \"hmac_key_base64\": \"").append(escapeJson(hmacKeyBase64)).append("\",\n");
        json.append("    \"hmac_hex\": \"").append(escapeJson(hmacSm3Hex)).append("\",\n");
        json.append("    \"hmac_base64\": \"").append(escapeJson(hmacSm3Base64)).append("\"\n");
        json.append("  },\n");

        // SM4
        json.append("  \"sm4\": {\n");
        json.append("    \"key_hex\": \"").append(escapeJson(sm4KeyHex)).append("\",\n");
        json.append("    \"key_base64\": \"").append(escapeJson(sm4KeyBase64)).append("\",\n");
        json.append("    \"iv_hex\": \"").append(escapeJson(sm4IvHex)).append("\",\n");
        json.append("    \"gcm_ciphertext_hex\": \"").append(escapeJson(sm4GcmHex)).append("\",\n");
        json.append("    \"gcm_ciphertext_base64\": \"").append(escapeJson(sm4GcmBase64)).append("\",\n");
        json.append("    \"gcm_cipher_tag_hex\": \"").append(escapeJson(sm4CipherTagHex)).append("\"\n");
        json.append("  }\n");

        json.append("}\n");

        // Write to file
        String outputPath = args.length > 0 ? args[0] : "testcase/java_go_test_data.json";
        try (FileWriter writer = new FileWriter(outputPath)) {
            writer.write(json.toString());
        }
        System.out.println("\nTest data saved to: " + outputPath);
        System.out.println("\n=== Java-Go test data generation complete! ===");
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}