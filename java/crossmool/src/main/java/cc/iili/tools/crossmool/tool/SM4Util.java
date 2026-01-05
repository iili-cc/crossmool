package cc.iili.tools.crossmool.tool;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import cc.iili.tools.crossmool.util.HexUtil;

/**
 * SM4 国密对称加密工具类（支持 ECB/CBC 模式） - 提供 Bouncy Castle 原生 API 和 JCA 标准 API 两种实现 -
 * 仅依赖 bcprov-jdkXXon，无其他第三方库
 */
public class SM4Util {

	static {
		// register Bouncy Castle Provider（avoid duplicate）
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static final String ALGORITHM_NAME = "SM4";
	private static final int KEY_SIZE_BITS = 128;
	private static final int KEY_SIZE_BYTES = KEY_SIZE_BITS / 8; // 16 bytes

	// ========================
	// 1. generate key
	// ========================

	/**
	 * generate 128 bits (16 bytes) random SM4 cryptography key (byte array)
	 */
	public static byte[] generateKey() {
		byte[] key = new byte[KEY_SIZE_BYTES];
		new java.security.SecureRandom().nextBytes(key);
		return key;
	}

	/**
	 * generate Hex format SM4 key (32 bytes)
	 */
	public static String generateKeyAsHex() {
		return HexUtil.encodeHexStr(generateKey());
	}

	/**
	 * 从十六进制字符串解析密钥（忽略大小写） parse SM4 key from Hex string to byte array
	 */
	public static byte[] parseHexKey(String hexKey) {
		return HexUtil.decodeHexStr(hexKey);
	}

	// ========================
	// 2. Native Bouncy Castle API Implementation (recommended for high-performance or embedded scenarios)
	// ========================

	/**
	 * Encrypts using the native Bouncy Castle API (ECB mode with PKCS7Padding).
	 *
	 * @param key       the 16-byte secret key
	 * @param plainText plaintext in UTF-8 encoding
	 * @return ciphertext as a hexadecimal string
	 */
	public static String encryptEcbNative(byte[] key, byte [] input) {
		validateKey(key);
		try {
			PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SM4Engine(), new PKCS7Padding());
			cipher.init(true, new KeyParameter(key));
			byte[] output = new byte[cipher.getOutputSize(input.length)];
			int len = cipher.processBytes(input, 0, input.length, output, 0);
			cipher.doFinal(output, len);

			return Hex.toHexString(output);
		} catch (Exception e) {
			throw new RuntimeException("SM4 native encryption failed", e);
		}
	}

	/**
	 * Decrypt using the native Bouncy Castle API (ECB mode with PKCS7Padding).
	 */
	public static String decryptEcbNative(byte[] key, String hexCipherText) {
		validateKey(key);
		try {
			byte[] cipherBytes = Hex.decode(hexCipherText);
			PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new SM4Engine(), new PKCS7Padding());
			cipher.init(false, new KeyParameter(key));

			byte[] output = new byte[cipher.getOutputSize(cipherBytes.length)];
			int len = cipher.processBytes(cipherBytes, 0, cipherBytes.length, output, 0);
			cipher.doFinal(output, len);

			return new String(output, StandardCharsets.UTF_8).trim();
		} catch (Exception e) {
			throw new RuntimeException("SM4 native decryption failed", e);
		}
	}

	// ========================
	// 3. JCA standard API implement（Compatible Java Cryptography Architecture）
	// ========================

	/**
	 * encrypt with JCA API（SM4/ECB/PKCS7Padding）
	 */
	public static String encryptEcbJca(byte[] key, String plainText) {
		validateKey(key);
		try {
			Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "BC");
			SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM_NAME);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec);

			byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			return Hex.toHexString(encrypted);
		} catch (Exception e) {
			throw new RuntimeException("SM4 JCA encryption failed", e);
		}
	}

	/**
	 * decrypt with JCA API（SM4/ECB/PKCS7Padding）
	 */
	public static String decryptEcbJca(byte[] key, String hexCipherText) {
		validateKey(key);
		try {
			byte[] cipherBytes = Hex.decode(hexCipherText);
			Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS7Padding", "BC");
			SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM_NAME);
			cipher.init(Cipher.DECRYPT_MODE, keySpec);

			byte[] decrypted = cipher.doFinal(cipherBytes);
			return new String(decrypted, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("SM4 JCA decryption failed", e);
		}
	}

	// ========================
	// helper method
	// ========================

	private static void validateKey(byte[] key) {
		if (key == null || key.length != KEY_SIZE_BYTES) {
			throw new IllegalArgumentException("SM4 key must be 16 bytes (128 bits)");
		}
	}

	// ========================
	// test case
	// ========================
	public static void main(String[] args) {
		String plainText = "Hello, 這是国密SM4測試數據";
		String hexKey = generateKeyAsHex();
		byte[] key = parseHexKey(hexKey);
		
		String encode = Base64.getEncoder().encodeToString(key);

		System.out.println("original text" + plainText);
		System.out.println("encryption key(HEX): " + hexKey);
		System.out.println("encryption key(Base64): " + encode);

		// 原生 API
		byte[] bytes = plainText.getBytes(StandardCharsets.UTF_8);
		String enc1 = encryptEcbNative(key, bytes);
		String dec1 = decryptEcbNative(key, enc1);
		System.out.println("\n[Native API]");
		System.out.println("encrypt result:" + enc1);
		System.out.println("decrypt result:" + dec1);

		// JCA API
		String enc2 = encryptEcbJca(key, plainText);
		String dec2 = decryptEcbJca(key, enc2);
		System.out.println("\n[JCA API]");
		System.out.println("encrypt result:" + enc2);
		System.out.println("decrypt result:" + dec2);

		// 验证一致性
		assert enc1.equals(enc2);
		assert plainText.equals(dec1) && plainText.equals(dec2);
		System.out.println("\n✅ test pass");
	}
}