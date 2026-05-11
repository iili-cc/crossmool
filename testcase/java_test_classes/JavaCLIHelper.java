package java_test_classes;

import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Java CLI helper for SM2/SM3/SM4 interop testing.
 * Called by Python orchestrator to run individual crypto operations.
 *
 * Commands:
 *   gen-keypair                → prints JSON {publicKey_hex, privateKey_hex}
 *   sm2-encrypt  <pt> <pub>    → prints ciphertext hex
 *   sm2-decrypt  <ct> <prv>    → prints plaintext
 *   sm2-sign     <msg> <prv>   → prints signature hex
 *   sm2-verify   <msg> <sig> <pub> → prints true/false
 *   sm3-digest   <msg>         → prints digest hex
 *   sm3-hmac     <key> <data>  → prints hmac hex
 *   sm4-encrypt  <pt> <key>    → prints ciphertext hex
 *   sm4-decrypt  <ct> <key>    → prints plaintext
 *   sm4-gen-key                → prints key hex
 */
public class JavaCLIHelper {
    
    private static final String USAGE =
        "Usage: java JavaCLIHelper <command> [args...]\n" +
        "  gen-keypair\n" +
        "  sm2-encrypt  <plaintext> <pubKeyHex>\n" +
        "  sm2-decrypt  <ciphertextHex> <prvKeyHex>\n" +
        "  sm2-sign     <message> <prvKeyHex>\n" +
        "  sm2-verify      <message> <sigHex> <pubKeyHex>\n" +
        "  sm2-verify-hex  <contentHex> <sigHex> <pubKeyHex>\n" +
        "  sm2-encrypt-hex <contentHex> <pubKeyHex>\n" +
        "  sm2-decrypt-hex <cipherHex> <prvKeyHex>\n" +
        "  sm3-digest   <message>\n" +
        "  sm3-hmac     <keyHex> <data>\n" +
        "  sm4-encrypt  <plaintext> <keyHex>\n" +
        "  sm4-decrypt  <ciphertextHex> <keyHex>\n" +
        "  sm4-gen-key\n";

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println(USAGE);
            System.exit(1);
            return;
        }

        String cmd = args[0];
        try {
            switch (cmd) {
                case "gen-keypair": handleGenKeypair(); break;
                case "sm2-encrypt": handleSm2Encrypt(args); break;
                case "sm2-decrypt": handleSm2Decrypt(args); break;
                case "sm2-sign":    handleSm2Sign(args); break;
                case "sm2-verify":    handleSm2Verify(args); break;
                case "sm2-verify-hex":  handleSm2VerifyHex(args); break;
                case "sm2-encrypt-hex": handleSm2EncryptHex(args); break;
                case "sm2-decrypt-hex": handleSm2DecryptHex(args); break;
                case "sm3-digest":  handleSm3Digest(args); break;
                case "sm3-hmac":    handleSm3Hmac(args); break;
                case "sm4-encrypt": handleSm4Encrypt(args); break;
                case "sm4-decrypt": handleSm4Decrypt(args); break;
                case "sm4-gen-key": handleSm4GenKey(); break;
                default:
                    System.err.println("Unknown command: " + cmd);
                    System.err.println(USAGE);
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    static void handleGenKeypair() throws Exception {
        SerialKeyPair kp = SM2Util.generateKeyPairHex();
        System.out.printf("{\"public_key\": \"%s\", \"private_key\": \"%s\"}%n",
            kp.getPublicKey(), kp.getPrivateKey());
        System.out.println("__RESULT_OK__");
    }

    static void handleSm2Encrypt(String[] args) throws Exception {
        if (args.length < 3) { System.err.println(USAGE); System.exit(1); return; }
        String result = SM2Util.encrypt(args[1], args[2]);
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    static void handleSm2Decrypt(String[] args) throws Exception {
        if (args.length < 3) { System.err.println(USAGE); System.exit(1); return; }
        String result = SM2Util.decrypt(args[1], args[2]);
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    static void handleSm2Sign(String[] args) throws Exception {
        if (args.length < 3) { System.err.println(USAGE); System.exit(1); return; }
        String result = SM2Util.sign(args[1], args[2]);
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    static void handleSm2Verify(String[] args) throws Exception {
        if (args.length < 4) { System.err.println(USAGE); System.exit(1); return; }
        boolean result = SM2Util.verify(args[1], args[3], args[2]);
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    /** Verify raw bytes: args are <content_hex> <sig_hex> <pub_hex> */
    static void handleSm2VerifyHex(String[] args) throws Exception {
        if (args.length < 4) { System.err.println(USAGE); System.exit(1); return; }
        byte[] content = HexUtil.decodeHexStr(args[1]);
        byte[] sig     = HexUtil.decodeHexStr(args[2]);
        byte[] pub     = HexUtil.decodeHexStr(args[3]);
        boolean result = SM2Util.verify(content, sig, pub);
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    /** Encrypt hex content bytes (avoids Windows cmdline encoding issues for non-ASCII) */
    static void handleSm2EncryptHex(String[] args) throws Exception {
        if (args.length < 3) { System.err.println(USAGE); System.exit(1); return; }
        byte[] content = HexUtil.decodeHexStr(args[1]);
        byte[] pub     = HexUtil.decodeHexStr(args[2]);
        byte[] result  = SM2Util.encryptToBytes(content, pub);
        System.out.println(HexUtil.encodeHexStr(result));
        System.out.println("__RESULT_OK__");
    }

    /** Decrypt hex ciphertext, returns hex plaintext (avoids cmdline encoding issues) */
    static void handleSm2DecryptHex(String[] args) throws Exception {
        if (args.length < 3) { System.err.println(USAGE); System.exit(1); return; }
        byte[] ct  = HexUtil.decodeHexStr(args[1]);
        byte[] prv = HexUtil.decodeHexStr(args[2]);
        byte[] result = SM2Util.decryptToBytes(ct, prv);
        System.out.println(HexUtil.encodeHexStr(result));
        System.out.println("__RESULT_OK__");
    }

    static void handleSm3Digest(String[] args) throws Exception {
        if (args.length < 2) { System.err.println(USAGE); System.exit(1); return; }
        String result = SM3Util.digestToStr(args[1]);
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    static void handleSm3Hmac(String[] args) throws Exception {
        if (args.length < 3) { System.err.println(USAGE); System.exit(1); return; }
        String result = SM3Util.hmacToStr(args[1], args[2]);
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    static void handleSm4Encrypt(String[] args) throws Exception {
        if (args.length < 3) { System.err.println(USAGE); System.exit(1); return; }
        byte[] key = HexUtil.decodeHexStr(args[2]);
        String result = SM4Util.encryptEcbNative(key, args[1].getBytes(StandardCharsets.UTF_8));
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    static void handleSm4Decrypt(String[] args) throws Exception {
        if (args.length < 3) { System.err.println(USAGE); System.exit(1); return; }
        byte[] key = HexUtil.decodeHexStr(args[2]);
        String result = SM4Util.decryptEcbNative(key, args[1]);
        System.out.println(result);
        System.out.println("__RESULT_OK__");
    }

    static void handleSm4GenKey() throws Exception {
        String key = SM4Util.generateKeyAsHex();
        System.out.println(key);
        System.out.println("__RESULT_OK__");
    }
}
