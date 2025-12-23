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
import org.bouncycastle.util.encoders.Hex;

import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.constant.SM2Constant;
import cn.hutool.crypto.SmUtil;
import cn.hutool.crypto.asymmetric.KeyType;
import cn.hutool.crypto.asymmetric.SM2;
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
    
    
    
    private static final SM2Engine sm2Engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
    
    /**
     * 
     * @param forEncryption, true means encrypt; false means decrypt
     * @param cryptoKey, if forEncryption is true, it is publicKey; else it is privateKey
     * @return
     */
    public static SM2Engine getSM2Engine(boolean forEncryption, String cryptoKey) {
        if(forEncryption) {
            ECPublicKeyParameters publicKeyParameters = SM2KeyUtil.convertX509BytesToECPublicKeyParameters(cryptoKey);
            sm2Engine.init(true, publicKeyParameters);
            return sm2Engine;
        }
        ECPrivateKeyParameters privateKeyParameters = SM2KeyUtil.convertX509BytesToECPrivateKeyParameters(cryptoKey);
        sm2Engine.init(false, privateKeyParameters);
        return sm2Engine;
    }
    
//    /**
//     * 
//     * @param original  utf-8 text
//     * @param publicKey Hex text
//     * @return Hex text
//     */
    public static byte[] encrypt(String content, String publicKey, Charset charset) {
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
        SM2Engine sm2Engine = getSM2Engine(true, publicKey);
        try {
            return sm2Engine.processBlock(contentBytes, 0, contentBytes.length);
        } catch (InvalidCipherTextException e) {
            log.error("SM2 encrypt error:", e);
            throw new RuntimeException("SM2 encrypt error:" + e.getMessage());
        }
    }
    public static byte[] encrypt(String content, String publicKey) {
        return encrypt(content, publicKey, StandardCharsets.UTF_8);
    }
    
    public static String encryptToHex(String content, String publicKey) {
        byte[] encryptedBytes = encrypt(content, publicKey);
        return Hex.toHexString(encryptedBytes);
        
    }
    public static String encryptToBase64(String content, String publicKey) {
        byte[] encryptedBytes = encrypt(content, publicKey);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    
    public static String decrypt(String secret, String privateKey) {
        SM2 sm2 = SmUtil.sm2(privateKey, null);
        return sm2.decryptStr(secret, KeyType.PrivateKey);
    }
    
    public static String sign(String original, String privateKey) {
        SM2 sm2 = SmUtil.sm2(privateKey, null);
        return sm2.signHex(original);
    }
    
    public static boolean verify(String dataHex, String publicKey, String signHex) {
        SM2 sm2 = SmUtil.sm2(null, publicKey);
        return sm2.verifyHex(dataHex, signHex);
    }
    /**
     * original text --> encodeHex --> encrypt --> return
     * @param original
     * @param publicKey
     * @return
     */
//    public static String hexEncrypt(String original, String publicKey) {
//        String hex = SM2Utils.encodeHexStr(original);
//        return SM2Utils.encrypt(hex, publicKey);
//    }
    /**
     * encrypted text --> decrypt --> decodeHex --> return
     * @param encrypted
     * @param privateKey
     * @return
     */
//    public static String decryptHex(String encrypted, String privateKey) {
//        String decrypt = SM2Utils.decrypt(encrypted, privateKey);
//        return SM2Utils.decodeHexStr(decrypt);
//    }
//    /**
//     * @Suggest
//     * original text --> encodeHex --> sign  --> wrap(data,sign) --> encrypt --> return
//     * @param original
//     * @param signPrivateKey
//     * @param encPublicKey
//     * @return
//     */
//    public static String hexSignEncrypt(String original, String signPrivateKey, String encPublicKey) {
//        String hex = SM2Utils.encodeHexStr(original);
//        String signature = SM2Utils.sign(hex, signPrivateKey);
//        String msg = JSONUtil.toJsonStr(new DataSignPair(hex, signature));
//        log.debug("msg:"+msg);
//        return SM2Utils.encrypt(msg, encPublicKey);
//    }
//    /**
//     * @Suggest
//     * encrypted text --> decrypt --> unwrap(data,sign) --> sign verify --> decodeHex --> return
//     * @param encrypted
//     * @param signPublicKey
//     * @param decPrivateKey
//     * @return
//     */
//    public static String decryptVerifyHex(String encrypted, String signPublicKey, String decPrivateKey) {
//        String decrypt = SM2Utils.decrypt(encrypted, decPrivateKey);
//        DataSignPair dataSignPair = DataSignPair.toBean(decrypt);
//        boolean verify = SM2Utils.verify(dataSignPair.getData(), signPublicKey, dataSignPair.getSign());
//        if(verify) {
//            return SM2Utils.decodeHexStr(dataSignPair.getData());
//        }
//        throw new RuntimeException("SM2 verify failed: " + dataSignPair.getData());
//        
//    }
    
//    
//    
//    /**
//     * @Deprecated suggest using the hexSignEncrypt to encrypt & decryptVerifyHex to decrypt, please @See the sample2 & sample3
//     * 
//     * 1. hex = SM2Utils.encodeHexStr
//     * 2. sign = SM2Utils.sign
//     * 3. wrap:message = hex + sign
//     * 4. SM2Utils.encrypt
//     * ******transfer-over-network*****
//     * 5. SM2Utils.decrypt
//     * 6. unwrap: hex = decrypt.hex, sign = decrypt.sign
//     * 7. SM2Utils.verify
//     * 8. SM2Utils.decodeHexStr
//     */
//    private static void sample() {
//        String original = "我是一只小小小鳥，我是一只小小小鳥， fly fly fly";
//        log.debug("original:" + original);
//        String hex = SM2Utils.encodeHexStr(original);
//        
//        KeyPair keyPair = SM2Utils.generateSM2SecretKey();//or exist private & public keys
//        
//        String sign = SM2Utils.sign(hex, keyPair.getPrivateKey());
//        
//        String message = "{\"data\":\""+hex+"\",\"sign\":\""+sign+"\"}";
//        
//        log.debug("message:" + message);
//        
//        KeyPair keyPair2 = SM2Utils.generateSM2SecretKey();//or exist private & public keys
//        
//        String encrypt = SM2Utils.encrypt(message, keyPair2.getPublicKey());
//        
//        log.debug("encrypt:"+encrypt);
//        
//        String decrypt = SM2Utils.decrypt(encrypt, keyPair2.getPrivateKey());
//        
//        log.debug("decrypt:" + decrypt);
//        
//        JsonNode jsonNode = JsonUtil.parseObject(decrypt);
//        String data = jsonNode.get("data").asText();
//        String signn = jsonNode.get("sign").asText();
//        log.debug("data:" + data);
//        log.debug("sign:" + signn);
//        
//        boolean verify = SM2Utils.verify(data, keyPair.getPublicKey(), signn);
//        
//        log.debug("verify:" + verify);
//        
//        String reOriginal = SM2Utils.decodeHexStr(data);
//        log.debug("reOriginal:" + reOriginal);
//        /**
//         *  original:我是一只小小小鳥，我是一只小小小鳥， fly fly fly
//            message:{"data":"e68891e698afe4b880e58faae5b08fe5b08fe5b08fe9b3a5efbc8ce68891e698afe4b880e58faae5b08fe5b08fe5b08fe9b3a5efbc8c20666c7920666c7920666c79","sign":"3044022036387da43bc99aa375d33506b920a417cbc8e68503937848f7148b7c23389be6022034f3b922ff0c1f2e636d9534e3791495fb07effffe4de3247defb08369f017ff"}
//            encrypt:04983a0cb8be71899043d97b72123f0d997b4f99e05ec2d8a29e5dd3abde482701e69304f8cc0c6bdb601fe1fd330b92835dd88749fd549ecc894eaa1a5b65e99990a2e50b64d6d677d1ad7b90057bbe52afd9f9638f545e19515d43e94b75f4669bd8299ba55c69efe49b188ec82f30b410663879d4a8cadb8f4a58ff77211949911096d931f3718f267144e7927b16db01674f068b26953f21124cbc65cc7dfae00a5f9c90b3ace0be175d9bab26ad93591de3024c666f72d0ee9429573a8f0518e0192f85b8cad7b352d509fe365c4b22f82b4331286fd36e62797c6089800338d85054d8caab7fd83b5f484a972909167f4008c9d04050269395fcc94daceba2fdb8ae74dbf42d56e2ee3eb62cebb76bb1ff51630c47d91d5cb37ad5f5ccd7f554baabcc63d5b396158852c647b84d4886af305fd7ee6bba6401f7489382fbbbb50fb73d64c82399d91791cef9b833eb486a9a37ecc0c52f784fcf8727f013c434e34069805c2bd43f8a0edf7d7196528813ac3423483b81babe2eb4cbc3b166e742e494
//            decrypt:{"data":"e68891e698afe4b880e58faae5b08fe5b08fe5b08fe9b3a5efbc8ce68891e698afe4b880e58faae5b08fe5b08fe5b08fe9b3a5efbc8c20666c7920666c7920666c79","sign":"3044022036387da43bc99aa375d33506b920a417cbc8e68503937848f7148b7c23389be6022034f3b922ff0c1f2e636d9534e3791495fb07effffe4de3247defb08369f017ff"}
//            data:e68891e698afe4b880e58faae5b08fe5b08fe5b08fe9b3a5efbc8ce68891e698afe4b880e58faae5b08fe5b08fe5b08fe9b3a5efbc8c20666c7920666c7920666c79
//            sign:3044022036387da43bc99aa375d33506b920a417cbc8e68503937848f7148b7c23389be6022034f3b922ff0c1f2e636d9534e3791495fb07effffe4de3247defb08369f017ff
//            verify:true
//            reOriginal:我是一只小小小鳥，我是一只小小小鳥， fly fly fly
//         */
//    }
//    
//    private static void sample2() {
//        String original = "我是一只小小小鳥，我是一只小小小鳥， fly fly fly";
////      KeyPair keyPair = SM2Utils.generateSM2SecretKey();//or exist private & public keys
////      log.debug("Encrypt private & public Keys:" + keyPair.getPrivateKey() + "; " + keyPair.getPublicKey());
////      KeyPair keyPair2 = SM2Utils.generateSM2SecretKey();//or exist private & public keys
////      log.debug("Sign private & public Keys:" + keyPair2.getPrivateKey() + ";" + keyPair2.getPublicKey());
////      String signedEncrypted = hexSignEncrypt(original, keyPair2.getPrivateKey(), keyPair.getPublicKey());
//        String encPublicKey = "04af5fa4521c22a7f383121a6550db7b7bf999f49f0b3d5f422ff73d77132b464c4c75d966036e603dba7f325bc2e502a9a7dd8e4cea55b1478717e98c919e8d87";
//        String signPrivateKey = "21e2fb92a99b2cc3fd459917c90ba0a063bc007479a90a4976af9dc3717406bc";
//        String signedEncrypted = hexSignEncrypt(original, signPrivateKey, encPublicKey);
//        log.debug("signedEncrypted:" + signedEncrypted);
//        
//        /**
//         * 11:33:39.325 [main] DEBUG com.gientech.insu.pubkit.sec.SM2Utils - Encrypt private & public Keys:2a079c73a9eb1474459adb0e087498e87c7c65e2258f8b4fd68f93169b779323; 04af5fa4521c22a7f383121a6550db7b7bf999f49f0b3d5f422ff73d77132b464c4c75d966036e603dba7f325bc2e502a9a7dd8e4cea55b1478717e98c919e8d87
//            11:33:39.332 [main] DEBUG com.gientech.insu.pubkit.sec.SM2Utils - Sign private & public Keys:21e2fb92a99b2cc3fd459917c90ba0a063bc007479a90a4976af9dc3717406bc;04801e433040fe91e33b1dcf5d9b96437cf2b11798532d78cb067492f2556d07c8b75f90ab41bf5d27a472380facdba49f8e7a05a158456fdfc6817b68ad518303
//            11:33:39.697 [main] DEBUG com.gientech.insu.pubkit.sec.SM2Utils - msg:{"data":"e68891e698afe4b880e58faae5b08fe5b08fe5b08fe9b3a5efbc8ce68891e698afe4b880e58faae5b08fe5b08fe5b08fe9b3a5efbc8c20666c7920666c7920666c79","sign":"3045022100e3e5aea57ac4307799d3de9a9bb4750c80d123fc6f92beef87e36db86b51940502201781635552ffdf8585a05f4ad2075c665ab3bd0004d381f867ddb3860784d69b"}
//            11:33:39.705 [main] DEBUG com.gientech.insu.pubkit.sec.SM2Utils - signedEncrypted:04b3a48f8c8aa555d7952274f52e89e54e9a771c3863c5048801ca85275da3464fb5d48e2bd541a077fa6112546c533568e687ddf640ce08a6efb5486ce505d474f2d58b7899269587d207b44d3b2031c28e2d930502fd2e9533414a843905ca23d7e73428ac7212ddd76e40286d3a2f0fda805e9d4da05b1312e477883a6fba459f37eb0b82b5cec464d4251a5b4781f3ba2287ad6b86a5626f907db6794178df21ddb3188398b359f2b11c70100588ac6b793c41698a428cffffe5e70656129e414f4c40ee0009090343dcb90725f908a312d9fa36774230028c5cea2827647aaea6f374591da6e5049e4c06b448264b859b8edd500c9fd81a400ba80b75e1287c7e3a3459b90c53b9975e5fb5d63eaaf5fb9e529e85c6507e34f91043d1d7cf7134e125e76ccc4809d0028924234e1eb01d0be199a61af905a0c327b7521b0ed5c28710a6591a059d1378378c804b618cefdb3a85621f97e5362a5b129ec60b9c12e30f505a3373c4094aab1bce3944bdaa25f9bb0590d9432cb653077160a5bdc21b0de3f364
//         */
//    }
//    
//    private static void sample3() {
//        String signedEncrypted = "04b3a48f8c8aa555d7952274f52e89e54e9a771c3863c5048801ca85275da3464fb5d48e2bd541a077fa6112546c533568e687ddf640ce08a6efb5486ce505d474f2d58b7899269587d207b44d3b2031c28e2d930502fd2e9533414a843905ca23d7e73428ac7212ddd76e40286d3a2f0fda805e9d4da05b1312e477883a6fba459f37eb0b82b5cec464d4251a5b4781f3ba2287ad6b86a5626f907db6794178df21ddb3188398b359f2b11c70100588ac6b793c41698a428cffffe5e70656129e414f4c40ee0009090343dcb90725f908a312d9fa36774230028c5cea2827647aaea6f374591da6e5049e4c06b448264b859b8edd500c9fd81a400ba80b75e1287c7e3a3459b90c53b9975e5fb5d63eaaf5fb9e529e85c6507e34f91043d1d7cf7134e125e76ccc4809d0028924234e1eb01d0be199a61af905a0c327b7521b0ed5c28710a6591a059d1378378c804b618cefdb3a85621f97e5362a5b129ec60b9c12e30f505a3373c4094aab1bce3944bdaa25f9bb0590d9432cb653077160a5bdc21b0de3f364";
//        String signPublicKey = "04801e433040fe91e33b1dcf5d9b96437cf2b11798532d78cb067492f2556d07c8b75f90ab41bf5d27a472380facdba49f8e7a05a158456fdfc6817b68ad518303";
//        String decPrivateKey = "2a079c73a9eb1474459adb0e087498e87c7c65e2258f8b4fd68f93169b779323";
//        String original = decryptVerifyHex(signedEncrypted, signPublicKey, decPrivateKey);
//        log.debug("original:" + original);
//    }
//    /**
//     * if App1 invoke App2, there should be 8 key pairs for the request & response, header & body, sign & crypto
//     * sign: sign-by-private-key, verify-by-public-key; crypto: encrypt-by-public-key, decrypt-by-private-key
//     * the privateKey & publicKey of the KeyPair should be HEX format string
//     * every App, should hold the privateKey by itself, and send the publicKey to other side
//     * @see sample2, sample3
//     */
//    private static void sample4() {
//        //App1 sign with keyPair1.privateKey, & encrypt with keyPair2.publicKey, then send the request message
//        //App2 receive the request message, then decrypt with keyPair2.privateKey, verify with the keyPair1.publicKey
//        //Thus, App2 get the original request message text, and process
//        KeyPair keyPair1 = generateSM2SecretKey();
//        KeyPair keyPair2 = generateSM2SecretKey();
//        //after the process
//        //App2 sign with keyPair3.privateKey, & encrypt with keyPair4.publicKey, then send the response message
//        //App1 receive the response message, then decrypt with keyPair4.privateKey, verify with the keyPair3.publicKey
//        //Thus, App1 get the original response message text
//        KeyPair keyPair3 = generateSM2SecretKey();
//        KeyPair keyPair4 = generateSM2SecretKey();
//    }
//    
//    
//    
//    public static void main(String[] args) {
////      String ss = "我是一只小小小鳥，我是一只小小小鳥， fly fly fly";
//////    ss = "dfiaejifiwe928394839%%$$";
////      String cc = HexUtil.encodeHexStr(ss);
////      log.debug(cc);
////      CharSequence c = (CharSequence) cc;
////      log.debug("c:" + c);
////      KeyPair signKeyPair = SM2Utils.generateSM2SecretKey();
////      signKeyPair.print();
////      String signHex = SM2Utils.sign(cc, signKeyPair.getPrivateKey());
////      log.debug("signHex:" + signHex);
////      boolean verify = SM2Utils.verify(cc, signKeyPair.getPublicKey(), signHex);
////      log.debug("verify:" + verify);
////      String tt = HexUtil.decodeHexStr(cc);
////      log.debug(tt);
////      String origin = "{\n" +
////              "  \"body\": {\n" +
////              "    \"damagePerson\": \"123465\",\n" +
////              "    \"partsId\": \"1472583690001\",\n" +
////              "    \"reviewResult\": \"F\",\n" +
////              "    \"remark\": \"\"\n" +
////              "  },\n" +
////              "  \"head\": {\n" +
////              "    \"timeStamp\": \"2024-01-12 00:00:00\",\n" +
////              "    \"transactionNo\": \"f490ea6b-7acf-445f-b5d7-2f8a78731559\",\n" +
////              "    \"userCode\": \"dsgj\",\n" +
////              "    \"passWord\": \"1234\"\n" +
////              "  }\n" +
////              "}";
////      System.out.println("原始参数: "+origin);
////      KeyPair signKeyPair = SM2Utils.generateSM2SecretKey();
////      KeyPair keyPair = SM2Utils.generateSM2SecretKey();
////      String signPrivateKey = signKeyPair.getPrivateKey();
////      String signPublicKey = signKeyPair.getPublicKey();
////      String privateKey = keyPair.getPrivateKey();
////      String publicKey = keyPair.getPublicKey();
////      System.out.println("签名私钥: "+signKeyPair.getPrivateKey());
////      System.out.println("签名公钥: "+signKeyPair.getPublicKey());
////      System.out.println("===================");
////      System.out.println("加密公钥: "+keyPair.getPublicKey());
////      System.out.println("解密私钥: "+keyPair.getPrivateKey());
//////        String encrypt = SM2Utils.hexSignEncrypt(origin, signKeyPair.getPrivateKey(), keyPair.getPublicKey());
////      String encrypt = SM2Utils.hexSignEncrypt(origin, signPrivateKey, publicKey);
////      System.out.println("encrypt: "+encrypt);
////      String decrypt = SM2Utils.decryptVerifyHex(encrypt,signPublicKey, privateKey);
////      System.out.println("decrypt: "+decrypt);
//
//        System.out.println(SM2Utils.decodeHexStr(SM2Utils.encodeHexStr("Pjpt111#")));
//        SM2Utils.sample();
////      SM2Utils.sample3();
//    }
    
    public static void main(String[] args) {
        SerialKeyPair keyPairStr = SM2Utils.generateKeyPairBase64();
        
    }


}