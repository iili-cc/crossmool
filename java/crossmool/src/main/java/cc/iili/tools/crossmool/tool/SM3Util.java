package cc.iili.tools.crossmool.tool;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cc.iili.tools.crossmool.util.Base64Util;
import cc.iili.tools.crossmool.util.HexUtil;
// import lombok.extern.slf4j.Slf4j; -- removed, see FIX-017

// @Slf4j -- removed, see FIX-017
public class SM3Util {
    private static final java.util.logging.Logger log = java.util.logging.Logger.getLogger(SM3Util.class.getName());

	static {
		// register Bouncy Castle Provider（avoid duplicate）
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
	}

	/**
	 * generate the SM3 digest by BouncyCastle API
	 */
	public static byte[] digest(byte[] input) {
		SM3Digest sm3Digest = new SM3Digest();
		sm3Digest.update(input, 0, input.length);
		byte[] digest = new byte[sm3Digest.getDigestSize()];
		sm3Digest.doFinal(digest, 0);
		return digest;
	}

	public static String digestToHex(byte[] input) {
		return HexUtil.encodeHexStr(digest(input));
	}
	
	public static String digestToStr(byte[] input, boolean toBase64) {
		byte[] digestBytes = digest(input);
		if(toBase64) {
			return Base64Util.encodeBase64Str(digestBytes);
		}
		return HexUtil.encodeHexStr(digestBytes);
	}
	
	public static String digestToStr(byte[] input) {
		return digestToHex(input);
	}
	
	public static String digestToStr(String input, Charset charset, boolean toBase64) {
		if(input == null || input.isBlank()) {
			throw new RuntimeException("input cannot be empty");
		}
		byte[] inputBytes = input.getBytes(charset);
		byte[] digestBytes = digest(inputBytes);
		if(toBase64) {
			return Base64Util.encodeBase64Str(digestBytes);
		}
		return HexUtil.encodeHexStr(digestBytes);
	}
	
	/**
	 * Mainly method by BouncyCastle API
	 * @param input
	 * @return
	 */
	public static String digestToStr(String input, boolean toBase64) {
		return digestToStr(input, StandardCharsets.UTF_8, toBase64);
	}
	/**
	 * Mainly method by BouncyCastle API
	 * @param input
	 * @return, Hex is the default output format 
	 */
	public static String digestToStr(String input) {
		return digestToStr(input, StandardCharsets.UTF_8, false);
	}
	

	/**
	 * generate the SM3 digest by JCA API(need to specify Provider as "BC")
	 */
	public static byte[] messageDigest(byte[] input) {
		try {
			MessageDigest messageDigest = MessageDigest.getInstance("SM3", "BC");
			return messageDigest.digest(input);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
			throw new RuntimeException("Error computing SM3 digest via JCA", e);
		}
	}

	public static String messageDigestToHex(byte[] input){
		return HexUtil.encodeHexStr(messageDigest(input));
	}
	public static String messageDigestToStr(byte[] input, boolean toBase64) {
		byte[] digestBytes = messageDigest(input);
		if(toBase64) {
			return Base64Util.encodeBase64Str(digestBytes);
		}
		return HexUtil.encodeHexStr(digestBytes);
	}
	
	public static String messageDigestToStr(byte[] input) {
		return messageDigestToHex(input);
	}
	
	public static String messageDigestToStr(String input, Charset charset, boolean toBase64) {
		if(input == null || input.isBlank()) {
			throw new RuntimeException("input cannot be empty");
		}
		byte[] inputBytes = input.getBytes(charset);
		byte[] digestBytes = messageDigest(inputBytes);
		if(toBase64) {
			return Base64Util.encodeBase64Str(digestBytes);
		}
		return HexUtil.encodeHexStr(digestBytes);
	}
	/**
	 * Mainly method by JCA API
	 * @param input
	 * @param toBase64
	 * @return
	 */
	public static String messageDigestToStr(String input, boolean toBase64) {
		return messageDigestToStr(input, StandardCharsets.UTF_8, toBase64);
	}
	/**
	 * Mainly method by JCA API
	 * @param input
	 * @return, Hex is the default output format
	 */
	public static String messageDigestToStr(String input) {
		return messageDigestToStr(input, StandardCharsets.UTF_8, false);
	}
	
	/**
	 * 
	 * @param keyLengthInBytes, should be >= 32
	 * @return
	 */
	public static byte[] generateHmacKey(int keyLengthInBytes) {
		if(keyLengthInBytes < 32) {
			throw new IllegalArgumentException("keyLengthInBytes must be bigger than or equal to 32.");
		}
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[keyLengthInBytes];
        secureRandom.nextBytes(key);
        return key;
    }
	
	public static String generateHmacKeyToStr(int keyLengthInBytes, boolean toBase64){
		byte[] hmacKeyBytes = generateHmacKey(keyLengthInBytes);
		if(toBase64) {
			return Base64Util.encodeBase64Str(hmacKeyBytes);
		}
		return HexUtil.encodeHexStr(hmacKeyBytes);
	}
	
	public static byte[] generateHmacKey() {
		return generateHmacKey(32);
	}
	
	public static String generateHmacKeyToStr(int keyLengthInBytes){
		return generateHmacKeyToStr(keyLengthInBytes, false);
	}
	
	public static String generateHmacKeyToStr(boolean toBase64){
		return generateHmacKeyToStr(32, toBase64);
	}
	
	public static String generateHmacKeyToStr(){
		return generateHmacKeyToStr(false);
	}
	
	public static byte[] generateHmacKey32() {
		return generateHmacKey(32);
	}
	public static byte[] generateHmacKey64() {
		return generateHmacKey(64);
	}
	
	
	
	

	/**
	 * HMAC-SM3 实现
	 * 
	 * 参数顺序约定：第 1 个参数为数据（原文），第 2 个参数为密钥（密码），其余参数分列 3,4,5...
	 */
	public static byte[] hmac(byte[] data, byte[] key) {
		//generate key parameter
		KeyParameter keyParameter = new KeyParameter(key);
		//generate SM3 digest
		SM3Digest digest = new SM3Digest();
		//generate HMac instance
		HMac mac = new HMac(digest);
		mac.init(keyParameter);
		mac.update(data, 0, data.length);
		//generate HMAC-SM3
		byte[] out = new byte[mac.getMacSize()];
		mac.doFinal(out, 0);
		return out;
	}
	/**
	 * 
	 * @param data, could be Hex string, Base64 string or utf-8 string
	 * @param key, must be Hex string or Base64 string
	 * @return
	 */
	public static byte[] hmac(String data, String key) {
		if(key == null || key.isBlank() || data == null || data.isBlank()) {
			throw new IllegalArgumentException("Key or data for HMAC-SM3 cannot be null");
		}
		byte[] keyBytes = null;
		byte[] dataBytes = null;
		if (HexUtil.isHexString(key)) {// both key and data are hex string
			keyBytes = HexUtil.decodeHexStr(key);
		}else if(Base64Util.isBase64String(key)) {
			keyBytes = Base64Util.decodeBase64Str(key);
		}else {
			throw new IllegalArgumentException("Key for HMAC-SM3 must be Hex string or Base64 string");
		}
		if (HexUtil.isHexString(data)) {// both key and data are base64 string
			dataBytes = HexUtil.decodeHexStr(data);
		}else if(Base64Util.isBase64String(data)) {
			dataBytes = Base64Util.decodeBase64Str(data);
		}else {
			dataBytes = data.getBytes(StandardCharsets.UTF_8);
		}
		// generate HMAC-SM3
		byte[] hmac = hmac(dataBytes, keyBytes);
		return hmac;
	}
	
	/**
	 * HMAC-SM3, output as Hex string(default) or Base64 string
	 */
	public static String hmacToStr(byte[] data, byte[] key, boolean toBase64) {
		byte[] hmac = hmac(data, key);
		if (toBase64) {
			return Base64.getEncoder().encodeToString(hmac);
		}
		return HexUtil.encodeHexStr(hmac);
	}
	/**
	 * HMAC-SM3, output as Hex string
	 */
	public static String hmacToStr(byte[] data, byte[] key) {
		byte[] hmac = hmac(data, key);
		return HexUtil.encodeHexStr(hmac);
	}
	/**
	 * 
	 * @param data, should be Hex string or Base64 string
	 * @param key, should be Hex string or Base64 string
	 * @param toBase64, output as Base64 string if true, otherwise as Hex string
	 * @return, HMAC-SM3 as Hex string or Base64 string
	 */
	public static String hmacToStr(String data, String key, boolean toBase64) {
		byte[] hmac = hmac(data, key);
		if (toBase64) {
			return Base64.getEncoder().encodeToString(hmac);
		}
		return HexUtil.encodeHexStr(hmac);
	}
	/**
	 * 
	 * @param data, should be Hex string or Base64 string
	 * @param key, should be Hex string or Base64 string
	 * @return, HMAC-SM3 as Hex string
	 */
	public static String hmacToStr(String data, String key) {
		return hmacToStr(data, key, false);
	}
	/**
	 * key and data must be both Hex string or both Base64 string
	 * @param data
	 * @param key 
	 * @param toBase64, output as Base64 string if true, otherwise as Hex string
	 * @return
	 */
	public static String hmacToStrWithSameFormatParams(String data, String key, boolean toBase64) {
		if(key == null || key.isBlank() || data == null || data.isBlank()) {
			throw new IllegalArgumentException("Key or data for HMAC-SM3 cannot be null");
		}
		byte[] keyBytes = null;
		byte[] dataBytes = null;
		if (HexUtil.isHexString(key) && HexUtil.isHexString(data)) {// both key and data are hex string
			keyBytes = HexUtil.decodeHexStr(key);
			dataBytes = HexUtil.decodeHexStr(data);
		}else if (Base64Util.isBase64String(key) && Base64Util.isBase64String(data)) {// both key and data are base64 string
			keyBytes = Base64Util.decodeBase64Str(key);
			dataBytes = Base64Util.decodeBase64Str(data);
		}else {
			throw new IllegalArgumentException("Key and data for HMAC-SM3 must be both Hex string or both Base64 string");
		}
		byte[] hmac = hmac(dataBytes, keyBytes);
		if (toBase64) {
			return Base64.getEncoder().encodeToString(hmac);
		}
		return HexUtil.encodeHexStr(hmac);
	}
	/**
	 * 
	 * @param data, key and data must be both Hex string or both Base64 string
	 * @param key, key and data must be both Hex string or both Base64 string
	 * @return, HMAC-SM3 as Hex string
	 */
	public static String hmacToStrWithSameFormatParams(String data, String key) {
		return hmacToStrWithSameFormatParams(data, key, false);
	}
	
	public static boolean hmacVerify(String data, String key, String receivedHmac) {
		byte[] hmacBytes = hmac(data, key);
		byte[] receivedHmacBytes = null;
		if(HexUtil.isHexString(receivedHmac)) {
			receivedHmacBytes = HexUtil.decodeHexStr(receivedHmac);
		}else if(Base64Util.isBase64String(receivedHmac)) {
			receivedHmacBytes = Base64Util.decodeBase64Str(receivedHmac);
		} else {
			throw new IllegalArgumentException("receivedHmac should be Hex string or Base64 string");
		}
		return Arrays.equals(hmacBytes, receivedHmacBytes);
		
	}

}
