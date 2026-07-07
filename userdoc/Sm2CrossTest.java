import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

public class Sm2CrossTest {
    public static void main(String[] args) throws Exception {
        String json = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        // Simple JSON extraction (avoid adding json lib)
        String encPub = extract(json, "enc_pub_hex");
        String encPriv = extract(json, "enc_priv_hex");
        String sigPub = extract(json, "sig_pub_hex");
        String sigPriv = extract(json, "sig_priv_hex");
        String plain1 = extract(json, "plain1");
        String plain2 = extract(json, "plain2");
        String ct1Hex = extract(json, "ct1_hex");
        String ct1B64 = extract(json, "ct1_b64");
        String ct2Hex = extract(json, "ct2_hex");
        String sig2Hex = extract(json, "sig2_hex");
        String ct2B64 = extract(json, "ct2_b64");
        String sig2B64 = extract(json, "sig2_b64");

        int pass = 0, fail = 0;
        try {
            // Self encrypt/decrypt
            String ct1 = SM2Util.encrypt(plain1, encPub);
            check("encrypt_hex", !ct1.isEmpty()); pass++; }
        catch (Exception e) { System.out.println("  encrypt_hex FAIL: " + e.getMessage()); fail++; }

        try {
            String ct1 = SM2Util.encrypt(plain1, encPub);
            String pt1 = SM2Util.decrypt(ct1, encPriv);
            check("decrypt_hex_self", pt1.equals(plain1)); pass++; }
        catch (Exception e) { System.out.println("  decrypt_hex_self FAIL: " + e.getMessage()); fail++; }

        try {
            String ct1b = SM2Util.encrypt(plain1, encPub, true);
            String pt1b = SM2Util.decrypt(ct1b, encPriv);
            check("decrypt_b64_self", pt1b.equals(plain1)); pass++; }
        catch (Exception e) { System.out.println("  decrypt_b64_self FAIL: " + e.getMessage()); fail++; }

        try {
            String ptPy = SM2Util.decrypt(ct1Hex, encPriv);
            check("decrypt_hex_py", ptPy.equals(plain1)); pass++; }
        catch (Exception e) { System.out.println("  decrypt_hex_py FAIL: " + e.getMessage()); fail++; }

        try {
            String ptPyB = SM2Util.decrypt(ct1B64, encPriv);
            check("decrypt_b64_py", ptPyB.equals(plain1)); pass++; }
        catch (Exception e) { System.out.println("  decrypt_b64_py FAIL: " + e.getMessage()); fail++; }

        try {
            CiphertextSignaturePair esp = SM2Util.encryptSign(plain2, encPub, sigPriv);
            check("encrypt_sign_hex", esp.getCiphertext() != null && !esp.getCiphertext().isEmpty()); pass++; }
        catch (Exception e) { System.out.println("  encrypt_sign_hex FAIL: " + e.getMessage()); fail++; }

        try {
            CiphertextSignaturePair esp = SM2Util.encryptSign(plain2, encPub, sigPriv);
            String vd = SM2Util.verifyDecrypt(esp.getCiphertext(), esp.getSignature(), sigPub, encPriv);
            check("verify_decrypt_hex_self", vd.equals(plain2)); pass++; }
        catch (Exception e) { System.out.println("  verify_decrypt_hex_self FAIL: " + e.getMessage()); fail++; }

        try {
            String vdPy = SM2Util.verifyDecrypt(ct2Hex, sig2Hex, sigPub, encPriv);
            check("verify_decrypt_hex_py", vdPy.equals(plain2)); pass++; }
        catch (Exception e) { System.out.println("  verify_decrypt_hex_py FAIL: " + e.getMessage()); fail++; }

        try {
            String vdPyB = SM2Util.verifyDecrypt(ct2B64, sig2B64, sigPub, encPriv);
            check("verify_decrypt_b64_py", vdPyB.equals(plain2)); pass++; }
        catch (Exception e) { System.out.println("  verify_decrypt_b64_py FAIL: " + e.getMessage()); fail++; }

        System.out.println("\n  " + pass + "/" + (pass+fail) + " passed");
        if (fail > 0) System.exit(1);
    }

    static String extract(String json, String key) {
        int start = json.indexOf("\"" + key + "\"") + key.length() + 4;
        int end = json.indexOf("\"", start);
        String val = json.substring(start, end);
        // Unescape
        return val.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n");
    }

    static void check(String name, boolean ok) {
        System.out.println("  " + name + " " + (ok ? "PASS" : "FAIL"));
    }
}
