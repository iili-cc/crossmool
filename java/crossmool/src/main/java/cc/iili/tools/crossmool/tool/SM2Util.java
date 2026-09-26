package cc.iili.tools.crossmool.tool;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.constant.SM2Constant;
import cc.iili.tools.crossmool.util.Base64Util;
import cc.iili.tools.crossmool.util.HexUtil;
import cc.iili.tools.crossmool.util.SM2KeyUtil;

/**
 * Encrypt only: use encrypt(String, String) to Hex, encrypt(String, String, true) to Base64
 * Decrypt only: use decrypt(String, String) from Hex, decrypt(String, String, true) from Base64
 * 
 * Sign only: use sign(String, String) to Hex, sign(String, String, true) to Base64
 * Verify only: use verify(String, String, String) from Hex, verify(String, String, String, true) from Base64
 * 
 * Encrypt & Sign: use encryptSign(String, String, String) to Hex, encryptSign(String, String, String, true) to Base64
 * Verify & Decrypt: use verifyDecrypt(String, String, String, String) from Hex, verifyDecrypt(String, String, String, String, true) from Base64
 * 
 * Encrypt & Sign with same format keys: encryptSignWithSameFormatKeys(String, String, String): 
 * 											if both keys are Hex string, output Hex string; if both keys are Base64 string, output Base64 string
 * 
 * charset: utf-8
 * encode: Hex / Base64
 * sign & encrypt use different keypairs
 *
 */
public class SM2Util {
    
    static {
    	// register Bouncy Castle Provider（avoid duplicate）
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    /**
     * generate a SM2 KeyPair by java.security.KeyPairGenerator
     * Just provide ASN.1/X.509
     * 
     * @return
     */
    public static KeyPair generateKeyPair() {
        ECGenParameterSpec sm2Spec = new ECGenParameterSpec(SM2Constant.CURVE_NAME_SM2);
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(SM2Constant.ALGORITHM, SM2Constant.PROVIDER);
            generator.initialize(sm2Spec);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            System.err.println("generateKeyPair error: " + e.getMessage());
            throw new RuntimeException("generateKeyPair error:" + e.getMessage());
        }
    }
    /**
     * generate a SM2 KeyPair by java.security.KeyPairGenerator
     * Just provide ASN.1/X.509 mode
     * 
     * @return
     */
    public static SerialKeyPair generateKeyPairBase64() {
        KeyPair keyPair = generateKeyPair();
        byte[] publicEncoded = keyPair.getPublic().getEncoded();
        byte[] privateEncoded = keyPair.getPrivate().getEncoded();
        String publicKeyStr = Base64.getEncoder().encodeToString(publicEncoded);
        String privateKeyStr = Base64.getEncoder().encodeToString(privateEncoded);
        SerialKeyPair serialKeyPair = new SerialKeyPair(publicKeyStr, privateKeyStr);
        // log.info removed - FIX-017
        return serialKeyPair;
    }
    /**
     * generate a SM2 KeyPair by java.security.KeyPairGenerator
     * Just provide ASN.1/X.509 encoded Hex string (particular start with "30" for public key), do not support the-mode-start-with-"04".
     * @return
     */
    public static SerialKeyPair generateKeyPairHex() {
        KeyPair keyPair = generateKeyPair();
        byte[] publicEncoded = keyPair.getPublic().getEncoded();
        byte[] privateEncoded = keyPair.getPrivate().getEncoded();
        String publicKeyStr = Hex.toHexString(publicEncoded);
        String privateKeyStr = Hex.toHexString(privateEncoded);
        SerialKeyPair serialKeyPair = new SerialKeyPair(publicKeyStr, privateKeyStr);
        // log.info removed - FIX-017
        return serialKeyPair;
    }
    /**
     * generate a SM2 KeyPair by BouncyCastle
     * @deprecated suggest using generateKeyPair(), java.security.KeyPairGenerator is better
     * @return
     */
    @Deprecated
    public static AsymmetricCipherKeyPair generateKeyPairBC() {
        ECDomainParameters domainParameters = SM2KeyUtil.getECDomainParameters();
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(domainParameters,new SecureRandom()));
        return generator.generateKeyPair();
    }
    
    /**
     * 
     * @param forEncryption, true means encrypt; false means decrypt
     * @param cryptoKey, if forEncryption is true, it is publicKey; else it is privateKey
     * @return
     */
    private static SM2Engine getSM2Engine(boolean forEncryption, byte[] cryptoKey) {
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        if(forEncryption) {
            ECPublicKeyParameters publicKeyParameters = SM2KeyUtil.convertX509BytesToECPublicKeyParameters(cryptoKey);
            sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
            return sm2Engine;
        }
        ECPrivateKeyParameters privateKeyParameters = SM2KeyUtil.convertPKCS8BytesToECPrivateKeyParameters(cryptoKey);
        sm2Engine.init(false, privateKeyParameters);
        return sm2Engine;
    }
    /************************************************************************************************
     * Basic encrypt method
     * @param content
     * @param publicKey
     * @return
     * **********************************************************************************************
     */
    public static byte[] encryptToBytes(byte[] content, byte[] publicKey) {
        if(content == null) {
            throw new RuntimeException("SM2 encrypt error: the content is null.");
        }
        if(publicKey == null) {
            throw new RuntimeException("SM2 encrypt error: the publicKey is null.");
        }
        SM2Engine sm2Engine = getSM2Engine(true, publicKey);
        try {
            return sm2Engine.processBlock(content, 0, content.length);
        } catch (InvalidCipherTextException e) {
            System.err.println("SM2 encrypt error: " + e.getMessage());
            throw new RuntimeException("SM2 encrypt error:" + e.getMessage());
        }
    }
    
    /**
     * 
     * @param content, the charset is specified by charset param
     * @param publicKey Hex text
     * @return Charset default is UTF-8, please input java.nio.charset.StandardCharsets.xxx if necessary
     */
    public static byte[] encryptToBytes(String content, String publicKey, Charset charset) {
        if(content == null || content.isEmpty() || content.trim().isEmpty()) {
            throw new RuntimeException("SM2 encrypt error: the content is null.");
        }
        if(publicKey == null || publicKey.isEmpty() || publicKey.trim().isEmpty()) {
            throw new RuntimeException("SM2 encrypt error: the publicKey is null.");
        }
        if(charset == null) {
            charset = StandardCharsets.UTF_8;
        }
        byte[] contentBytes = content.getBytes(charset);
        byte[] publicKeyBytes = SM2KeyUtil.convertStringToBytes(publicKey);
        return encryptToBytes(contentBytes, publicKeyBytes);
    }
    /**
     * 
     * @param content, default charset is UTF-8
     * @param publicKey, Hex text or Base64 text
     * @return
     */
    public static byte[] encryptToBytes(String content, String publicKey) {
        return encryptToBytes(content, publicKey, StandardCharsets.UTF_8);
    }
    
    public static String encryptToHex(String content, String publicKey) {
        byte[] encryptedBytes = encryptToBytes(content, publicKey);
        return Hex.toHexString(encryptedBytes);
        
    }
    public static String encryptToBase64(String content, String publicKey) {
        byte[] encryptedBytes = encryptToBytes(content, publicKey);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    /**
     * Suggest: if the publicKey is Hex string, and the output is also Hex string
     *          if the publicKey is Base64 string, and the output is also Base64 string
     *          But this rule is not mandatory.
     * @param content
     * @param publicKey
     * @param toBase64, true means output Base64 string; false means output Hex string
     * @return
     */
    public static String encrypt(String content, String publicKey, boolean toBase64) {
        return toBase64 ? encryptToBase64(content, publicKey) : encryptToHex(content, publicKey);
    }
    /**
     * Mainly used encrypt method.
     * @param content
     * @param publicKey
     * @return, Hex is the default output format
     */
    public static String encrypt(String content, String publicKey) {
        return encrypt(content, publicKey, false);
    }
    
    /************************************************************************************************
     * Basic decrypt method
     * @param content
     * @param privateKey
     * @return
     * **********************************************************************************************
     */
    public static byte[] decryptToBytes(byte[] content, byte[] privateKey) {
        if(content == null) {
            throw new RuntimeException("SM2 decrypt error: the content is null.");
        }
        if(privateKey == null) {
            throw new RuntimeException("SM2 decrypt error: the privateKey is null.");
        }
        SM2Engine sm2Engine = getSM2Engine(false, privateKey);
        try {
            return sm2Engine.processBlock(content, 0, content.length);
        } catch (InvalidCipherTextException e) {
            System.err.println("SM2 decrypt error: " + e.getMessage());
            throw new RuntimeException("SM2 decrypt error:" + e.getMessage());
        }
    }
    
    /**
     * 
     * @param content  
     * @param privateKey Hex text
     * @return Charset default is UTF-8, please input java.nio.charset.StandardCharsets.xxx if necessary
     */
    public static byte[] decryptToBytes(String content, String privateKey) {
        if(content == null || content.isEmpty() || content.trim().isEmpty()) {
            throw new RuntimeException("SM2 decrypt error: the content is null.");
        }
        if(privateKey == null || privateKey.isEmpty() || privateKey.trim().isEmpty()) {
            throw new RuntimeException("SM2 decrypt error: the privateKey is null.");
        }
        boolean isHex = HexUtil.isHexString(content);
        byte[] contentBytes = isHex ? HexUtil.decodeHexStr(content) : Base64.getDecoder().decode(content);
        
        byte[] privateKeyBytes = SM2KeyUtil.convertStringToBytes(privateKey);
        return decryptToBytes(contentBytes, privateKeyBytes);
    }
    /**
     * 
     * @param content
     * @param publicKey, Hex text or Base64 text
     * @param charset, please input java.nio.charset.StandardCharsets.xxx if necessary, if input=null, default is UTF-8
     * @return
     */
    public static String decryptToCharset(String content, String privateKey, Charset charset) {
        byte[] decryptedBytes = decryptToBytes(content, privateKey);
        if(charset == null) {
            charset = StandardCharsets.UTF_8;
        }
        return new String(decryptedBytes, charset);
    }
    /**
     * Mainly used decrypt method.
     * Suggest: if the privateKey is Hex string, and the input is also Hex string
     *          if the privateKey is Base64 string, and the input is also Base64 string
     *          But this rule is not mandatory.
     * @param content
     * @param privateKey
     * @return the output format charset is UTF-8
     */
    public static String decrypt(String content, String privateKey) {
        return decryptToCharset(content, privateKey, StandardCharsets.UTF_8);
    }
    
    /**************************************************************************************************
     * Basic sign method
     * @param original
     * @param privateKey
     * @return
     * **********************************************************************************************
     */
    private static final String DEFAULT_USER_ID = "1234567812345678";
    private static final byte[] DEFAULT_USER_ID_BYTES = DEFAULT_USER_ID.getBytes(StandardCharsets.UTF_8);
    /**
     * 
     * @param forSign
     * @param signKeyBytes, if forSign is true, it is privateKey; else it is publicKey
     * @return
     */
    private static SM2Signer getSM2Signer(boolean forSign, byte[] signKeyBytes) {
        return getSM2Signer(forSign, signKeyBytes, DEFAULT_USER_ID_BYTES);
    }

    /**
     * 
     * @param forSign
     * @param signKeyBytes, if forSign is true, it is privateKey; else it is publicKey
     * @param userIdBytes, custom SM2 user ID; if null or empty, fall back to the default value
     * @return
     */
    private static SM2Signer getSM2Signer(boolean forSign, byte[] signKeyBytes, byte[] userIdBytes) {
        byte[] userId = (userIdBytes == null || userIdBytes.length == 0) ? DEFAULT_USER_ID_BYTES : userIdBytes;
        SM2Signer sm2Signer = new SM2Signer();
        if (forSign) {
            ECPrivateKeyParameters privateKeyParameters = SM2KeyUtil.convertPKCS8BytesToECPrivateKeyParameters(signKeyBytes);
            ParametersWithID privateParam = new ParametersWithID(privateKeyParameters, userId);
            sm2Signer.init(true, privateParam);
            return sm2Signer;
        }
        ECPublicKeyParameters publicKeyParameters = SM2KeyUtil.convertX509BytesToECPublicKeyParameters(signKeyBytes);
        ParametersWithID publicParam = new ParametersWithID(publicKeyParameters, userId);
        sm2Signer.init(false, publicParam);
        return sm2Signer;
    }
    
    public static byte[] sign(byte[] content, byte[] privateKey) {
        return sign(content, privateKey, DEFAULT_USER_ID_BYTES);
    }

    /**
     * Sign with a custom SM2 user ID (e.g. ID card number, phone number, email).
     * @param content
     * @param privateKey
     * @param userId custom SM2 user ID bytes; if null or empty, fall back to the default value
     * @return
     */
    public static byte[] sign(byte[] content, byte[] privateKey, byte[] userId) {
        if(content == null) {
            throw new RuntimeException("SM2 sign error: the content is null.");
        }
        if(privateKey == null) {
            throw new RuntimeException("SM2 sign error: the privateKey is null.");
        }
        SM2Signer sm2Signer = getSM2Signer(true, privateKey, userId);
        sm2Signer.update(content, 0, content.length);
        try {
            return sm2Signer.generateSignature();
        } catch (Exception e) {
            throw new RuntimeException("SM2 sign error:" + e.getMessage(), e);
        }
    }

    public static byte[] sign(String content, String privateKey, Charset charset) {
        return sign(content, privateKey, null, charset);
    }

    /**
     * Sign with a custom SM2 user ID (e.g. ID card number, phone number, email).
     * @param content
     * @param privateKey
     * @param userId custom SM2 user ID (UTF-8 encoded); if null or empty, fall back to the default value
     * @param charset content charset; if null, defaults to UTF-8
     * @return
     */
    public static byte[] sign(String content, String privateKey, String userId, Charset charset) {
        if(content == null || content.isEmpty()) {
            throw new RuntimeException("SM2 sign error: the content is null.");
        }
        byte[] privateKeyBytes = SM2KeyUtil.convertStringToBytes(privateKey);
        byte[] userIdBytes = (userId == null || userId.isEmpty()) ? DEFAULT_USER_ID_BYTES : userId.getBytes(StandardCharsets.UTF_8);
        if(charset == null) {
            charset = StandardCharsets.UTF_8;
        }
        byte[] contentBytes = content.getBytes(charset);
        return sign(contentBytes, privateKeyBytes, userIdBytes);
    }
    
    public static String signToHex(String content, String privateKey) {
        byte[] signBytes = sign(content, privateKey, StandardCharsets.UTF_8);
        return Hex.toHexString(signBytes);
    }
    
    public static String signToBase64(String content, String privateKey) {
        byte[] signBytes = sign(content, privateKey, StandardCharsets.UTF_8);
        return Base64.getEncoder().encodeToString(signBytes);
    }
    /**
     * Suggest: if the privateKey is Hex string, and the output is also Hex string
     *          if the privateKey is Base64 string, and the output is also Base64 string
     *          But this rule is not mandatory.
     * @param content
     * @param privateKey
     * @param toBase64, true means output Base64 string; false means output Hex string
     * @return
     */
    public static String sign(String content, String privateKey, boolean toBase64) {
        return toBase64 ? signToBase64(content, privateKey) : signToHex(content, privateKey);
    }
    /**
     * Mainly used sign method.
     * @param content
     * @param privateKey
     * @return, Hex is the default output format
     */
    public static String sign(String content, String privateKey) {
        return sign(content, privateKey, false);
    }
    
    /**************************************************************************************************
     * Basic verify method
     * @param content
     * @param publicKeyBytes
     * @param signature
     * @return
     * **********************************************************************************************
     */
    public static boolean verify(byte[] content, byte[] publicKeyBytes, byte[] signature) {
        return verify(content, publicKeyBytes, signature, DEFAULT_USER_ID_BYTES);
    }

    /**
     * Verify with a custom SM2 user ID (must match the one used at signing time).
     * @param content
     * @param publicKeyBytes
     * @param signature
     * @param userId custom SM2 user ID bytes; if null or empty, fall back to the default value
     * @return
     */
    public static boolean verify(byte[] content, byte[] publicKeyBytes, byte[] signature, byte[] userId) {
        if(content == null) {
            throw new RuntimeException("SM2 verify error: the content is null.");
        }
        if(publicKeyBytes == null) {
            throw new RuntimeException("SM2 verify error: the publicKeyBytes is null.");
        }
        if(signature == null) {
            throw new RuntimeException("SM2 verify error: the signature is null.");
        }
        SM2Signer sm2Signer = getSM2Signer(false, publicKeyBytes, userId);
        sm2Signer.update(content, 0, content.length);
        
        return sm2Signer.verifySignature(signature);
    }
    
    public static boolean verify(String content, String publicKey, String signature, Charset charset) {
        if(content == null || content.isEmpty()) {
            throw new RuntimeException("SM2 verify error: the content is null.");
        }
        if(publicKey == null || publicKey.isEmpty()) {
            throw new RuntimeException("SM2 verify error: the publicKey is null.");
        }
        if(signature == null || signature.isEmpty()) {
            throw new RuntimeException("SM2 verify error: the signature is null.");
        }
        byte[] publicKeyBytes = SM2KeyUtil.convertStringToBytes(publicKey);
        byte[] signatureBytes = SM2KeyUtil.convertStringToBytes(signature);
        if(charset == null) {
            charset = StandardCharsets.UTF_8;
        }
        byte[] contentBytes = content.getBytes(charset);
        
        return verify(contentBytes, publicKeyBytes, signatureBytes);
    }
    
    public static boolean verify(String content, String publicKey, String signature) {
        return verify(content, publicKey, signature, StandardCharsets.UTF_8);
    }

    /**
     * Verify with a custom SM2 user ID (must match the one used at signing time).
     * @param content
     * @param publicKey
     * @param signature
     * @param userId custom SM2 user ID (UTF-8 encoded); if null or empty, fall back to the default value
     * @return
     */
    public static boolean verify(String content, String publicKey, String signature, String userId) {
        if(content == null || content.isEmpty()) {
            throw new RuntimeException("SM2 verify error: the content is null.");
        }
        if(publicKey == null || publicKey.isEmpty()) {
            throw new RuntimeException("SM2 verify error: the publicKey is null.");
        }
        if(signature == null || signature.isEmpty()) {
            throw new RuntimeException("SM2 verify error: the signature is null.");
        }
        byte[] publicKeyBytes = SM2KeyUtil.convertStringToBytes(publicKey);
        byte[] signatureBytes = SM2KeyUtil.convertStringToBytes(signature);
        byte[] userIdBytes = (userId == null || userId.isEmpty()) ? DEFAULT_USER_ID_BYTES : userId.getBytes(StandardCharsets.UTF_8);
        return verify(content.getBytes(StandardCharsets.UTF_8), publicKeyBytes, signatureBytes, userIdBytes);
    }
    
    /**
     * 
     * @param content
     * @param encPublicKey
     * @param signPrivateKey
     * @param toBase64, true means the ciphertext & signature are Base64 string; false means the ciphertext & signature is Hex string
     * @return
     */
    public static CiphertextSignaturePair encryptSign(String content,  String encPublicKey, String signPrivateKey, boolean toBase64) {
        String encrypted = encrypt(content, encPublicKey, toBase64);
        String signature = sign(encrypted, signPrivateKey, toBase64);
        return new CiphertextSignaturePair(encrypted, signature);
    }
    /**
     * Mainly used encrypt & sign method.
     * @param content
     * @param encPublicKey, could be Hex string or Base64 string
     * @param signPrivateKey, could be Hex string or Base64 string
     * @return , Hex is the default output format
     */
    public static CiphertextSignaturePair encryptSign(String content, String encPublicKey, String signPrivateKey) {
        return encryptSign(content, encPublicKey, signPrivateKey, false);
    }
    /**
     * 
     * @param content
     * @param encPublicKey, should be Hex string
     * @param signPrivateKey, should be Hex string
     * @return, Hex is the output format
     */
    public static CiphertextSignaturePair encryptSignWithHexKeys(String content, String encPublicKey, String signPrivateKey) {
    	boolean hexEncPublicKey = HexUtil.isHexString(encPublicKey);
    	boolean hexSignPrivateKey = HexUtil.isHexString(signPrivateKey);
    	if(hexEncPublicKey && hexSignPrivateKey) {
			return encryptSign(content, encPublicKey, signPrivateKey, false);
    	}
    	throw new RuntimeException("SM2 encryptSignWithHexKeys error: the encPublicKey and signPrivateKey must be both Hex string.");
    }
    /**
     * 
     * @param content
     * @param encPublicKey, should be Base64 string
     * @param signPrivateKey, should be Base64 string
     * @return, Base64 is the output format
     */
    public static CiphertextSignaturePair encryptSignWithBase64Keys(String content, String encPublicKey, String signPrivateKey) {
    	boolean base64EncPublicKey = Base64Util.isBase64String(encPublicKey);
    	boolean base64SignPrivateKey = Base64Util.isBase64String(signPrivateKey);
    	if(base64EncPublicKey && base64SignPrivateKey) {
    		return encryptSign(content, encPublicKey, signPrivateKey, true);
    	}
    	throw new RuntimeException("SM2 encryptSignWithBase64Keys error: the encPublicKey and signPrivateKey must be both Base64 string.");
    }
    /**
     * 
     * @param content
     * @param encPublicKey, could be Hex string or Base64 string
     * @param signPrivateKey, must be same format as encPublicKey, if encPublicKey is Hex string, signPrivateKey must be Hex string too; if encPublicKey is Base64 string, signPrivateKey must be Base64 string too
     * @return, same format as the input keys
     */
    public static CiphertextSignaturePair encryptSignWithSameFormatKeys(String content, String encPublicKey, String signPrivateKey) {
    	boolean hexEncPublicKey = HexUtil.isHexString(encPublicKey);
    	boolean hexSignPrivateKey = HexUtil.isHexString(signPrivateKey);
    	if(hexEncPublicKey && hexSignPrivateKey) {
    		return encryptSign(content, encPublicKey, signPrivateKey, false);
    	}
    	boolean base64EncPublicKey = Base64Util.isBase64String(encPublicKey);
    	boolean base64SignPrivateKey = Base64Util.isBase64String(signPrivateKey);
    	if(base64EncPublicKey && base64SignPrivateKey) {
    		return encryptSign(content, encPublicKey, signPrivateKey, true);
    	}
    	throw new RuntimeException("SM2 encryptSignWithSameFormatKeys error: the encPublicKey and signPrivateKey must be both Hex string or both Base64 string.");
    }
    
    
    /**************************************************************************************************
     * Mainly used verify & decrypt method.
     * @param content
     * @param signature
     * @param signPublicKey
     * @param decPrivateKey
     * @return, if verify success, return the decrypted content; else throw RuntimeException
     * **********************************************************************************************
     */
    public static String verifyDecrypt(String content, String signature, String signPublicKey, String decPrivateKey) {
        boolean verify = verify(content, signPublicKey, signature);
        if(verify) {
            return decrypt(content, decPrivateKey);
        }
        throw new RuntimeException("SM2 verify failed: " + content);
    }
    
    public static String verifyDecrypt(CiphertextSignaturePair cipherSigPair, String signPublicKey, String decPrivateKey) {
        return verifyDecrypt(cipherSigPair.getCiphertext(), cipherSigPair.getSignature(), signPublicKey, decPrivateKey);
    }

    // ========================
    // PEM Export/Import
    // ========================

    /**
     * Export public key DER bytes as PEM string (X.509 SubjectPublicKeyInfo).
     */
    public static String exportPublicKeyPem(byte[] publicKeyDer) {
        return toPem("PUBLIC KEY", publicKeyDer);
    }

    /**
     * Export private key DER bytes as PEM string (PKCS#8 PrivateKeyInfo).
     */
    public static String exportPrivateKeyPem(byte[] privateKeyDer) {
        return toPem("PRIVATE KEY", privateKeyDer);
    }

    /**
     * Import PEM-encoded public key, returning raw DER bytes.
     */
    public static byte[] importPublicKeyPem(String pem) {
        return fromPem(pem, "PUBLIC KEY");
    }

    /**
     * Import PEM-encoded private key, returning raw DER bytes.
     */
    public static byte[] importPrivateKeyPem(String pem) {
        return fromPem(pem, "PRIVATE KEY");
    }

    private static String toPem(String type, byte[] der) {
        String b64 = Base64.getEncoder().encodeToString(der);
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            int end = Math.min(i + 64, b64.length());
            sb.append(b64, i, end).append('\n');
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }

    private static byte[] fromPem(String pem, String type) {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int start = pem.indexOf(begin);
        int finish = pem.indexOf(end);
        if (start == -1 || finish == -1) {
            throw new IllegalArgumentException("Invalid PEM: missing " + type + " boundaries");
        }
        String b64 = pem.substring(start + begin.length(), finish).replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }

}