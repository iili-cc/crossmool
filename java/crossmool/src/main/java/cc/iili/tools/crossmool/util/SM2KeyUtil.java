package cc.iili.tools.crossmool.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

import cc.iili.tools.crossmool.constant.SM2Constant;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SM2KeyUtil {
    
    /**
     * for the SM2 curve, the parameters are fixed.
     * @return
     */
    public static final ECDomainParameters getECDomainParameters() {
        X9ECParameters x9ecParameters = GMNamedCurves.getByName(SM2Constant.CURVE_NAME_SM2);
        return new ECDomainParameters(x9ecParameters);
    }
    
    public static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance("EC", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            log.error("获取KeyFactory失败: {}", e.getMessage(), e);
            throw new RuntimeException("Get KeyFactory instance failed.", e);
        }
    }
    
    /**
     * Convert the key string to byte array. It could support both Hex and Base64 formats.
     * @param keyStr, could be Hex string or Base64 string
     * @return
     */
    public static byte[] convertStringToBytes(String keyStr) {
        if (keyStr == null || keyStr.trim().isEmpty()) {
            throw new IllegalArgumentException("The keyStr must not be null.");
        }
        keyStr = keyStr.trim();
        if (HexUtil.isHexString(keyStr)) {
            return HexUtil.decodeHexStr(keyStr);
        } else {
            // 默认按Base64处理
            return Base64.getDecoder().decode(keyStr);
        }
    }
    
    
    /**
     * @param publicKeyBytes, Just support ASN.1/X.509 encoded
     * @return
     */
    public static PublicKey convertX509BytesToPublicKey(byte[] publicKeyBytes) {
        // 使用X.509格式创建公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = getKeyFactory();
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            log.error("创建公钥失败: {}", e.getMessage(), e);
            throw new RuntimeException("Convert the publicKeyBytes to java.security.PublicKey failed.", e);
        }
    }
    /**
     * convert the X.509 encoded public key bytes to ECPublicKeyParameters, and build the domain parameters internally.
     * @param publicKeyBytes
     * @return
     */
    public static ECPublicKeyParameters convertX509BytesToECPublicKeyParameters(byte[] publicKeyBytes) {
        PublicKey publicKey = convertX509BytesToPublicKey(publicKeyBytes);
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECDomainParameters domainParameters = getECDomainParameters();
        return new ECPublicKeyParameters(ecPublicKey.getQ(), domainParameters);
    }
    /**
     * same with convertX509BytesToECPublicKeyParameters(byte[]), but the input is String format.
     * @param publicKeyStr
     * @return
     */
    public static ECPublicKeyParameters convertX509StrToECPublicKeyParameters(String publicKeyStr) {
        byte[] publicKeyBytes = convertStringToBytes(publicKeyStr);
        return convertX509BytesToECPublicKeyParameters(publicKeyBytes);
    }
    
    /**
     * @param privateKeyBytes, Just support ASN.1/X.509 encoded
     * @return
     */
//    public static PrivateKey convertX509BytesToPrivateKey(byte[] privateKeyBytes) {
//        // 使用X.509格式创建公钥
//        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(privateKeyBytes);
//        KeyFactory keyFactory = getKeyFactory();
//        try {
//            return keyFactory.generatePrivate(keySpec);
//        } catch (InvalidKeySpecException e) {
//            log.error("创建公钥失败: {}", e.getMessage(), e);
//            throw new RuntimeException("Convert the privateKeyBytes to java.security.PrivateKey failed.", e);
//        }
//    }
    public static PrivateKey convertPKCS8BytesToPrivateKey(byte[] privateKeyBytes) {
        // 使用X.509格式创建公钥
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = getKeyFactory();
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            log.error("创建公钥失败: {}", e.getMessage(), e);
            throw new RuntimeException("Convert the privateKeyBytes to java.security.PrivateKey failed.", e);
        }
    }
    /**
     * convert the X.509 encoded private key bytes to ECPrivateKeyParameters, and build the domain parameters internally.
     * @param privateKeyBytes
     * @return
     */
    public static ECPrivateKeyParameters convertPKCS8BytesToECPrivateKeyParameters(byte[] privateKeyBytes) {
        PrivateKey privateKey = convertPKCS8BytesToPrivateKey(privateKeyBytes);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        ECDomainParameters domainParameters = getECDomainParameters();
        return new ECPrivateKeyParameters(ecPrivateKey.getD(), domainParameters);
    }
    /**
     * same with convertX509BytesToECPrivateKeyParameters(byte[]), but the input is String format.
     * @param privateKeyStr
     * @return
     */
    public static ECPrivateKeyParameters convertX509StrToECPrivateKeyParameters(String privateKeyStr) {
        byte[] privateKeyBytes = convertStringToBytes(privateKeyStr);
        return convertPKCS8BytesToECPrivateKeyParameters(privateKeyBytes);
    }

}
