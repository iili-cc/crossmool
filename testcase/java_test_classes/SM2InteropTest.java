package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class SM2InteropTest {
    public static void main(String[] args) throws Exception {
        String mode = args[0];
        
        if (mode.equals("encrypt")) {
            // Read content from file (base64 encoded to preserve special chars)
            String contentB64 = args[1];
            String encPublicKey = args[2];
            String signPrivateKey = args[3];
            
            String content = new String(Base64.getDecoder().decode(contentB64), "UTF-8");
            CiphertextSignaturePair result = SM2Util.encryptSign(content, encPublicKey, signPrivateKey, false);
            System.out.println(result.getCiphertext() + "\t" + result.getSignature());
            
        } else if (mode.equals("verify_decrypt")) {
            // Read input from JSON file
            String inputFile = args[1];
            String inputJson = new String(Files.readAllBytes(Paths.get(inputFile)), "UTF-8");
            
            // Simple JSON parsing
            String ciphertextHex = extractJsonField(inputJson, "ciphertext_hex");
            String signatureHex = extractJsonField(inputJson, "signature_hex");
            String signPublicKey = extractJsonField(inputJson, "sign_public_key_hex");
            String decPrivateKey = extractJsonField(inputJson, "dec_private_key_hex");
            
            String decrypted = SM2Util.verifyDecrypt(ciphertextHex, signatureHex, signPublicKey, decPrivateKey);
            // Output as Base64 to preserve special chars
            String b64 = Base64.getEncoder().encodeToString(decrypted.getBytes("UTF-8"));
            System.out.println("SUCCESS:" + b64);
        }
    }
    
    static String extractJsonField(String json, String key) {
        String searchKey = "\"" + key + "\":\u0020*\"";
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) throw new RuntimeException("Field not found: " + key);
        // Find the colon after key
        int colon = json.indexOf(':', idx);
        // Find the opening quote of value
        int openQuote = json.indexOf('"', colon);
        // Find the closing quote
        int closeQuote = json.indexOf('"', openQuote + 1);
        // Handle escaped quotes
        while (closeQuote > 0 && json.charAt(closeQuote - 1) == '\\' && json.charAt(closeQuote - 2) != '\\') {
            closeQuote = json.indexOf('"', closeQuote + 1);
        }
        return json.substring(openQuote + 1, closeQuote);
    }
}
