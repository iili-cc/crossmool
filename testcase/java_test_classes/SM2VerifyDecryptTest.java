package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class SM2VerifyDecryptTest {
    public static void main(String[] args) throws Exception {
        String inputFile = args[0];
        String inputJson = new String(Files.readAllBytes(Paths.get(inputFile)), "UTF-8");
        
        String ciphertextHex = extractField(inputJson, "ciphertext_hex");
        String signatureHex = extractField(inputJson, "signature_hex");
        String signPublicKey = extractField(inputJson, "sign_public_key_hex");
        String decPrivateKey = extractField(inputJson, "dec_private_key_hex");
        
        String decrypted = SM2Util.verifyDecrypt(ciphertextHex, signatureHex, signPublicKey, decPrivateKey);
        String b64 = Base64.getEncoder().encodeToString(decrypted.getBytes("UTF-8"));
        System.out.println("SUCCESS:" + b64);
    }
    
    static String extractField(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) throw new RuntimeException("Field not found: " + key);
        int colon = json.indexOf(':', idx);
        int openQuote = json.indexOf('"', colon);
        int closeQuote = openQuote + 1;
        while (closeQuote < json.length()) {
            if (json.charAt(closeQuote) == '"' && json.charAt(closeQuote - 1) != '\\') break;
            if (json.charAt(closeQuote) == '"' && json.charAt(closeQuote - 1) == '\\' && json.charAt(closeQuote - 2) == '\\') break;
            closeQuote++;
        }
        return json.substring(openQuote + 1, closeQuote);
    }
}
