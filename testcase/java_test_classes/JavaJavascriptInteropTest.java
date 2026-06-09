package testcase;

import cc.iili.tools.crossmool.tool.*;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JavaJavascriptInteropTest {
    
    public static void main(String[] args) {
        String mode = args[0];
        
        try {
            switch (mode) {
                case "sm2_encrypt_hex":
                    testSm2EncryptHex(args[1], args[2]);
                    break;
                case "sm2_encrypt_base64":
                    testSm2EncryptBase64(args[1], args[2]);
                    break;
                case "sm2_decrypt_hex":
                    testSm2DecryptHex(args[1], args[2]);
                    break;
                case "sm2_decrypt_base64":
                    testSm2DecryptBase64(args[1], args[2]);
                    break;
                case "sm2_sign_hex":
                    testSm2SignHex(args[1], args[2]);
                    break;
                case "sm2_sign_base64":
                    testSm2SignBase64(args[1], args[2]);
                    break;
                case "sm2_verify_hex":
                    testSm2VerifyHex(args[1], args[2], args[3]);
                    break;
                case "sm2_verify_base64":
                    testSm2VerifyBase64(args[1], args[2], args[3]);
                    break;
                case "sm2_encrypt_sign_hex":
                    testSm2EncryptSignHex(args[1], args[2], args[3]);
                    break;
                case "sm2_encrypt_sign_base64":
                    testSm2EncryptSignBase64(args[1], args[2], args[3]);
                    break;
                case "sm2_verify_decrypt_hex":
                    testSm2VerifyDecryptHex(args[1], args[2], args[3], args[4]);
                    break;
                case "sm2_verify_decrypt_base64":
                    testSm2VerifyDecryptBase64(args[1], args[2], args[3], args[4]);
                    break;
                case "sm3_digest":
                    testSm3Digest(args[1]);
                    break;
                case "sm3_hmac":
                    testSm3Hmac(args[1], args[2]);
                    break;
                case "sm4_encrypt_hex":
                    testSm4EncryptHex(args[1], args[2]);
                    break;
                case "sm4_encrypt_base64":
                    testSm4EncryptBase64(args[1], args[2]);
                    break;
                case "sm4_decrypt_hex":
                    testSm4DecryptHex(args[1], args[2]);
                    break;
                case "sm4_decrypt_base64":
                    testSm4DecryptBase64(args[1], args[2]);
                    break;
                default:
                    System.err.println("Unknown mode: " + mode);
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    static void testSm2EncryptHex(String contentB64, String publicKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String cipherHex = SM2Util.encrypt(content, publicKey, false);
        System.out.println(cipherHex);
    }
    
    static void testSm2EncryptBase64(String contentB64, String publicKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String cipherBase64 = SM2Util.encrypt(content, publicKey, true);
        System.out.println(cipherBase64);
    }
    
    static void testSm2DecryptHex(String cipherHex, String privateKey) {
        String plain = SM2Util.decrypt(cipherHex, privateKey);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm2DecryptBase64(String cipherBase64, String privateKey) {
        String plain = SM2Util.decrypt(cipherBase64, privateKey);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm2SignHex(String contentB64, String privateKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String sigHex = SM2Util.sign(content, privateKey, false);
        System.out.println(sigHex);
    }
    
    static void testSm2SignBase64(String contentB64, String privateKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String sigBase64 = SM2Util.sign(content, privateKey, true);
        System.out.println(sigBase64);
    }
    
    static void testSm2VerifyHex(String contentB64, String publicKey, String sigHex) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        boolean valid = SM2Util.verify(content, publicKey, sigHex);
        System.out.println(valid ? "true" : "false");
    }
    
    static void testSm2VerifyBase64(String contentB64, String publicKey, String sigBase64) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        boolean valid = SM2Util.verify(content, publicKey, sigBase64);
        System.out.println(valid ? "true" : "false");
    }
    
    static void testSm2EncryptSignHex(String contentB64, String encPubKey, String signPrivKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        CiphertextSignaturePair pair = SM2Util.encryptSign(content, encPubKey, signPrivKey, false);
        System.out.println(pair.getCiphertext() + "\t" + pair.getSignature());
    }
    
    static void testSm2EncryptSignBase64(String contentB64, String encPubKey, String signPrivKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        CiphertextSignaturePair pair = SM2Util.encryptSign(content, encPubKey, signPrivKey, true);
        System.out.println(pair.getCiphertext() + "\t" + pair.getSignature());
    }
    
    static void testSm2VerifyDecryptHex(String cipherHex, String sigHex, String signPubKey, String decPrivKey) {
        String plain = SM2Util.verifyDecrypt(cipherHex, sigHex, signPubKey, decPrivKey);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm2VerifyDecryptBase64(String cipherBase64, String sigBase64, String signPubKey, String decPrivKey) {
        String plain = SM2Util.verifyDecrypt(cipherBase64, sigBase64, signPubKey, decPrivKey);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm3Digest(String contentB64) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String digestHex = SM3Util.digestToStr(content);
        System.out.println(digestHex);
    }
    
    static void testSm3Hmac(String keyHex, String contentB64) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String hmacHex = SM3Util.hmacToStr(keyHex, content);
        System.out.println(hmacHex);
    }
    
    static void testSm4EncryptHex(String contentB64, String keyHex) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        byte[] key = cc.iili.tools.crossmool.util.HexUtil.decodeHexStr(keyHex);
        String cipherBase64 = SM4Util.encryptGcmJca(key, content);
        System.out.println(cipherBase64);
    }
    
    static void testSm4EncryptBase64(String contentB64, String keyBase64) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        byte[] key = Base64.getDecoder().decode(keyBase64);
        String cipherBase64 = SM4Util.encryptGcmJca(key, content);
        System.out.println(cipherBase64);
    }
    
    static void testSm4DecryptHex(String cipherBase64, String keyHex) {
        byte[] key = cc.iili.tools.crossmool.util.HexUtil.decodeHexStr(keyHex);
        String plain = SM4Util.decryptGcmJca(key, cipherBase64);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm4DecryptBase64(String cipherBase64, String keyBase64) {
        byte[] key = Base64.getDecoder().decode(keyBase64);
        String plain = SM4Util.decryptGcmJca(key, cipherBase64);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
}
