import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Verify Go-generated SM2/SM3/SM4 test data
 */
public class VerifyGoEncryptSignData {

    public static void main(String[] args) throws Exception {
        String inputPath = args.length > 0 ? args[0] : "testcase/go_java_test_data.json";
        
        System.out.println("=== Java Verify Go-Generated SM Data ===");
        System.out.println("Reading test data from: " + inputPath);
        
        String jsonContent = new String(Files.readAllBytes(Paths.get(inputPath)), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper();
        JsonNode data = mapper.readTree(jsonContent);
        
        String testMessage = data.get("test_message").asText();
        System.out.println("Test Message: " + testMessage);
        
        boolean allPassed = true;
        
        // ========== SM2 Verification ==========
        System.out.println("\n--- SM2 Verification ---");
        
        JsonNode sm2 = data.get("sm2");
        String pubKeyHex = sm2.get("public_key_hex").asText();
        String privKeyHex = sm2.get("private_key_hex").asText();
        String pubKeyBase64 = sm2.get("public_key_base64").asText();
        String privKeyBase64 = sm2.get("private_key_base64").asText();
        String ciphertextHex = sm2.get("ciphertext_hex").asText();
        String ciphertextBase64 = sm2.get("ciphertext_base64").asText();
        String signatureHex = sm2.get("signature_hex").asText();
        String signatureBase64 = sm2.get("signature_base64").asText();
        
        JsonNode encSignHex = sm2.get("encrypt_sign").get("hex");
        JsonNode encSignBase64 = sm2.get("encrypt_sign").get("base64");
        
        // Verify SM2 decrypt (Hex)
        try {
            String pt = SM2Util.decrypt(ciphertextHex, privKeyHex);
            if (testMessage.equals(pt)) {
                System.out.println("PASS: SM2 Decrypt (Hex)");
            } else {
                System.out.println("FAIL: SM2 Decrypt (Hex) - got: " + pt);
                allPassed = false;
            }
        } catch (Exception e) {
            System.out.println("FAIL: SM2 Decrypt (Hex): " + e.getMessage());
            allPassed = false;
        }
        
        // Verify SM2 decrypt (Base64)
        try {
            String pt = SM2Util.decrypt(ciphertextBase64, privKeyBase64);
            if (testMessage.equals(pt)) {
                System.out.println("PASS: SM2 Decrypt (Base64)");
            } else {
                System.out.println("FAIL: SM2 Decrypt (Base64) - got: " + pt);
                allPassed = false;
            }
        } catch (Exception e) {
            System.out.println("FAIL: SM2 Decrypt (Base64): " + e.getMessage());
            allPassed = false;
        }
        
        // Verify SM2 signature (Hex)
        try {
            boolean ok = SM2Util.verify(testMessage, pubKeyHex, signatureHex);
            if (ok) {
                System.out.println("PASS: SM2 Verify (Hex)");
            } else {
                System.out.println("FAIL: SM2 Verify (Hex) - signature invalid");
                allPassed = false;
            }
        } catch (Exception e) {
            System.out.println("FAIL: SM2 Verify (Hex): " + e.getMessage());
            allPassed = false;
        }
        
        // Verify SM2 signature (Base64)
        try {
            boolean ok = SM2Util.verify(testMessage, pubKeyBase64, signatureBase64);
            if (ok) {
                System.out.println("PASS: SM2 Verify (Base64)");
            } else {
                System.out.println("FAIL: SM2 Verify (Base64) - signature invalid");
                allPassed = false;
            }
        } catch (Exception e) {
            System.out.println("FAIL: SM2 Verify (Base64): " + e.getMessage());
            allPassed = false;
        }
        
        // Verify SM2 EncryptSign (Hex)
        try {
            CiphertextSignaturePair pair = new CiphertextSignaturePair(
                encSignHex.get("ciphertext").asText(),
                encSignHex.get("signature").asText()
            );
            String pt = SM2Util.verifyDecrypt(pair, pubKeyHex, privKeyHex);
            if (testMessage.equals(pt)) {
                System.out.println("PASS: SM2 VerifyDecrypt (Hex)");
            } else {
                System.out.println("FAIL: SM2 VerifyDecrypt (Hex) - got: " + pt);
                allPassed = false;
            }
        } catch (Exception e) {
            System.out.println("FAIL: SM2 VerifyDecrypt (Hex): " + e.getMessage());
            allPassed = false;
        }
        
        // Verify SM2 EncryptSign (Base64)
        try {
            CiphertextSignaturePair pair = new CiphertextSignaturePair(
                encSignBase64.get("ciphertext").asText(),
                encSignBase64.get("signature").asText()
            );
            String pt = SM2Util.verifyDecrypt(pair, pubKeyBase64, privKeyBase64);
            if (testMessage.equals(pt)) {
                System.out.println("PASS: SM2 VerifyDecrypt (Base64)");
            } else {
                System.out.println("FAIL: SM2 VerifyDecrypt (Base64) - got: " + pt);
                allPassed = false;
            }
        } catch (Exception e) {
            System.out.println("FAIL: SM2 VerifyDecrypt (Base64): " + e.getMessage());
            allPassed = false;
        }
        
        // ========== SM3 Verification ==========
        System.out.println("\n--- SM3 Verification ---");
        
        JsonNode sm3 = data.get("sm3");
        String digestHex = sm3.get("digest_hex").asText();
        String digestBase64 = sm3.get("digest_base64").asText();
        String hmacKeyHex = sm3.get("hmac_key_hex").asText();
        String hmacKeyBase64 = sm3.get("hmac_key_base64").asText();
        String hmacHex = sm3.get("hmac_hex").asText();
        String hmacBase64 = sm3.get("hmac_base64").asText();
        
        // Verify SM3 digest (Hex)
        String computedDigestHex = SM3Util.digestToStr(testMessage, false);
        if (digestHex.equals(computedDigestHex)) {
            System.out.println("PASS: SM3 Digest (Hex)");
        } else {
            System.out.println("FAIL: SM3 Digest (Hex) - expected: " + digestHex + ", got: " + computedDigestHex);
            allPassed = false;
        }
        
        // Verify SM3 digest (Base64)
        String computedDigestBase64 = SM3Util.digestToStr(testMessage, true);
        if (digestBase64.equals(computedDigestBase64)) {
            System.out.println("PASS: SM3 Digest (Base64)");
        } else {
            System.out.println("FAIL: SM3 Digest (Base64) - expected: " + digestBase64 + ", got: " + computedDigestBase64);
            allPassed = false;
        }
        
        // Verify HMAC-SM3 (Hex)
        String computedHmacHex = SM3Util.hmacToStr(hmacKeyHex, testMessage, false);
        if (hmacHex.equals(computedHmacHex)) {
            System.out.println("PASS: HMAC-SM3 (Hex)");
        } else {
            System.out.println("FAIL: HMAC-SM3 (Hex) - expected: " + hmacHex + ", got: " + computedHmacHex);
            allPassed = false;
        }
        
        // Verify HMAC-SM3 (Base64)
        String computedHmacBase64 = SM3Util.hmacToStr(hmacKeyBase64, testMessage, true);
        if (hmacBase64.equals(computedHmacBase64)) {
            System.out.println("PASS: HMAC-SM3 (Base64)");
        } else {
            System.out.println("FAIL: HMAC-SM3 (Base64) - expected: " + hmacBase64 + ", got: " + computedHmacBase64);
            allPassed = false;
        }
        
        // ========== SM4-GCM Verification ==========
        System.out.println("\n--- SM4-GCM Verification ---");
        
        JsonNode sm4 = data.get("sm4");
        String sm4KeyHex = sm4.get("key_hex").asText();
        byte[] sm4KeyBytes = HexUtil.decodeHexStr(sm4KeyHex);
        String gcmCiphertextBase64 = sm4.get("gcm_ciphertext_base64").asText();
        
        // Verify SM4-GCM decrypt (use Base64 format as expected by Java API)
        try {
            String decrypted = SM4Util.decryptGcmNativeToString(sm4KeyBytes, gcmCiphertextBase64);
            if (testMessage.equals(decrypted)) {
                System.out.println("PASS: SM4-GCM Decrypt");
            } else {
                System.out.println("FAIL: SM4-GCM Decrypt - got: " + decrypted);
                allPassed = false;
            }
        } catch (Exception e) {
            System.out.println("FAIL: SM4-GCM Decrypt: " + e.getMessage());
            allPassed = false;
        }
        
        // ========== Summary ==========
        System.out.println("\n=== Verification Summary ===");
        if (allPassed) {
            System.out.println("ALL TESTS PASSED!");
        } else {
            System.out.println("SOME TESTS FAILED!");
            System.exit(1);
        }
    }
}