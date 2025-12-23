package cc.iili.tools.crossmool.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
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
     * Convert the key string to byte array. It could support both Hex and Base64 formats.
     * @param keyStr
     * @return
     */
    public static byte[] convertStringToBytes(String keyStr) {
        keyStr = keyStr.trim();
        if (HexUtil.isHexString(keyStr)) {
            return HexUtil.decodeHexStr(keyStr);
        } else {
            // 默认按Base64处理
            return Base64.getDecoder().decode(keyStr);
        }
    }
    
    public static final ECDomainParameters getECDomainParameters() {
        X9ECParameters x9ecParameters = GMNamedCurves.getByName(SM2Constant.CURVE_NAME_SM2);
        ECDomainParameters domainParameters = new ECDomainParameters(x9ecParameters);
        return domainParameters;
    }
    
    /**
     * @param publicKeyBytes, Just support ASN.1/X.509 encoded
     * @return
     */
    public static PublicKey convertX509BytesToPublicKey(byte[] publicKeyBytes) {
        // 使用X.509格式创建公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            log.error("创建公钥失败: {}", e.getMessage(), e);
            throw new RuntimeException("Convert the publicKeyBytes to java.security.PublicKey failed.", e);
        }
    }
    
    public static ECPublicKeyParameters convertX509BytesToECPublicKeyParameters(byte[] publicKeyBytes) {
        PublicKey publicKey = convertX509BytesToPublicKey(publicKeyBytes);
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECDomainParameters domainParameters = getECDomainParameters();
        return new ECPublicKeyParameters(ecPublicKey.getQ(), domainParameters);
    }
    
    public static ECPublicKeyParameters convertX509BytesToECPublicKeyParameters(String publicKeyStr) {
        byte[] publicKeyBytes = convertStringToBytes(publicKeyStr);
        return convertX509BytesToECPublicKeyParameters(publicKeyBytes);
    }
    
    
    
    
    /**
     * @param privateKeyBytes, Just support ASN.1/X.509 encoded
     * @return
     */
    public static PrivateKey convertX509BytesToPrivateKey(byte[] privateKeyBytes) {
        // 使用X.509格式创建公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(privateKeyBytes);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            log.error("创建公钥失败: {}", e.getMessage(), e);
            throw new RuntimeException("Convert the privateKeyBytes to java.security.PrivateKey failed.", e);
        }
    }
    
    public static ECPrivateKeyParameters convertX509BytesToECPrivateKeyParameters(byte[] privateKeyBytes) {
        PrivateKey privateKey = convertX509BytesToPrivateKey(privateKeyBytes);
        ECPrivateKey ecPrivateKey = (ECPrivateKey) privateKey;
        ECDomainParameters domainParameters = getECDomainParameters();
        return new ECPrivateKeyParameters(ecPrivateKey.getD(), domainParameters);
    }
    
    public static ECPrivateKeyParameters convertX509BytesToECPrivateKeyParameters(String privateKeyStr) {
        byte[] privateKeyBytes = convertStringToBytes(privateKeyStr);
        return convertX509BytesToECPrivateKeyParameters(privateKeyBytes);
    }

}
