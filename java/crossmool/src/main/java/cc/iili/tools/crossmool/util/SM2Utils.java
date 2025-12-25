package cc.iili.tools.crossmool.util;
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
import org.bouncycastle.util.encoders.Hex;

import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.constant.SM2Constant;
import lombok.extern.slf4j.Slf4j;

/**
 * 
 * charset: utf-8
 * encode: Hex
 * sign & encrypt use different keypairs
 *
 */
@Slf4j
public class SM2Utils {
    
    
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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
            log.error("generateKeyPair error:", e);
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
        log.info("\npublicKeyStr:" + publicKeyStr + "\nprivateKeyStr:" + privateKeyStr);
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
        log.info("\npublicKeyStr:" + publicKeyStr + "\nprivateKeyStr:" + privateKeyStr);
        return serialKeyPair;
    }
    /**
     * generate a SM2 KeyPair by BouncyCastle
     * @deprecated suggest using generateKeyPair(), java.security.KeyPairGenerator is better
     * @return
     */
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
    public static SM2Engine getSM2Engine(boolean forEncryption, byte[] cryptoKey) {
        SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
        if(forEncryption) {
            ECPublicKeyParameters publicKeyParameters = SM2KeyUtil.convertX509BytesToECPublicKeyParameters(cryptoKey);
            sm2Engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
            return sm2Engine;
        }
        ECPrivateKeyParameters privateKeyParameters = SM2KeyUtil.convertPKCS8BytesToECPrivateKeyParameters(cryptoKey);
        sm2Engine.init(false, new ParametersWithRandom(privateKeyParameters, new SecureRandom()));
        return sm2Engine;
    }
    
    public static SM2Engine getSM2Engine(boolean forEncryption, String cryptoKey) {
        byte[] cryptoKeyBytes = SM2KeyUtil.convertStringToBytes(cryptoKey);
        return getSM2Engine(forEncryption, cryptoKeyBytes);
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
            log.error("SM2 encrypt error:", e);
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
            throw new RuntimeException("SM2 encrypt error: the content is null.");
        }
        if(privateKey == null) {
            throw new RuntimeException("SM2 encrypt error: the privateKey is null.");
        }
        SM2Engine sm2Engine = getSM2Engine(false, privateKey);
        try {
            return sm2Engine.processBlock(content, 0, content.length);
        } catch (InvalidCipherTextException e) {
            log.error("SM2 decrypt error:", e);
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
            throw new RuntimeException("SM2 encrypt error: the content is null.");
        }
        if(privateKey == null || privateKey.isEmpty() || privateKey.trim().isEmpty()) {
            throw new RuntimeException("SM2 encrypt error: the publicKey is null.");
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
    private static final String USER_ID = "0123456789ABCDEF";
    private static final byte[] USER_ID_BYTES = USER_ID.getBytes(StandardCharsets.UTF_8);
    /**
     * 
     * @param forSign
     * @param signKey, if forSign is true, it is privateKey; else it is publicKey
     * @return
     */
    public static SM2Signer getSM2Signer(boolean forSign, byte[] signKeyBytes) {
        SM2Signer sm2Signer = new SM2Signer();
        if (forSign) {
            ECPrivateKeyParameters privateKeyParameters = SM2KeyUtil.convertPKCS8BytesToECPrivateKeyParameters(signKeyBytes);
            ParametersWithID privateParam = new ParametersWithID(privateKeyParameters, USER_ID_BYTES);
//            sm2Signer.init(true, new ParametersWithRandom(privateParam, new SecureRandom()));
            sm2Signer.init(true, privateParam);
            return sm2Signer;
        }
        ECPublicKeyParameters publicKeyParameters = SM2KeyUtil.convertX509BytesToECPublicKeyParameters(signKeyBytes);
        ParametersWithID publicParam = new ParametersWithID(publicKeyParameters, USER_ID_BYTES);
//        sm2Signer.init(false, new ParametersWithRandom(publicParam, new SecureRandom()));
        sm2Signer.init(false, publicParam);
        return sm2Signer;
    }
    
    public static SM2Signer getSM2Signer(boolean forSign, String signKey) {
        byte[] signKeyBytes = SM2KeyUtil.convertStringToBytes(signKey);
        return getSM2Signer(forSign, signKeyBytes);
    }
    
    public static byte[] sign(byte[] content, byte[] privateKey) {
        if(content == null) {
            throw new RuntimeException("SM2 sign error: the content is null.");
        }
        if(privateKey == null) {
            throw new RuntimeException("SM2 sign error: the privateKey is null.");
        }
        SM2Signer sm2Signer = getSM2Signer(true, privateKey);
        sm2Signer.update(content, 0, content.length);
        try {
            return sm2Signer.generateSignature();
        } catch (Exception e) {
            log.error("SM2 sign error:", e);
            throw new RuntimeException("SM2 sign error:" + e.getMessage());
        }
    }
    public static byte[] sign(String content, String privateKey, Charset charset) {
        byte[] privateKeyBytes = SM2KeyUtil.convertStringToBytes(privateKey);
        if(charset == null) {
            charset = StandardCharsets.UTF_8;
        }
        byte[] contentBytes = content.getBytes(charset);
        return sign(contentBytes, privateKeyBytes);
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
     * @param data
     * @param publicKey
     * @param sign
     * @return
     * **********************************************************************************************
     */
    public static boolean verify(byte[] content, byte[] signature, byte[] publicKeyBytes) {
        if(content == null) {
            throw new RuntimeException("SM2 verify error: the content is null.");
        }
        if(signature == null) {
            throw new RuntimeException("SM2 verify error: the signature is null.");
        }
        if(publicKeyBytes == null) {
            throw new RuntimeException("SM2 verify error: the publicKeyBytes is null.");
        }
        SM2Signer sm2Signer = getSM2Signer(false, publicKeyBytes);
        sm2Signer.update(content, 0, content.length);
        
        return sm2Signer.verifySignature(signature);
    }
    
    public static boolean verify(String content, String publicKey, String signature, Charset charset) {
        byte[] publicKeyBytes = SM2KeyUtil.convertStringToBytes(publicKey);
        byte[] signatureBytes = SM2KeyUtil.convertStringToBytes(signature);
        if(charset == null) {
            charset = StandardCharsets.UTF_8;
        }
        byte[] contentBytes = content.getBytes(charset);
        
        return verify(contentBytes, signatureBytes, publicKeyBytes);
    }
    
    public static boolean verify(String content, String publicKey, String signature) {
        return verify(content, publicKey, signature, StandardCharsets.UTF_8);
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
        String signature = sign(content, signPrivateKey, toBase64);
        return new CiphertextSignaturePair(encrypted, signature);
    }
    /**
     * Mainly used encrypt & sign method.
     * @param content
     * @param encPublicKey
     * @param signPrivateKey
     * @return , Hex is the default output format
     */
    public static CiphertextSignaturePair encryptSign(String content,  String encPublicKey, String signPrivateKey) {
        return encryptSign(content, encPublicKey, signPrivateKey, false);
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
    
    public static void main(String[] args) {
        SerialKeyPair keyPairBase64 = generateKeyPairBase64();
        System.out.println("Generated KeyPair (Base64):\n" + keyPairBase64);
        SerialKeyPair keyPairHex = generateKeyPairHex();
        System.out.println("Generated KeyPair (Hex):\n" + keyPairHex);
        
    }


}