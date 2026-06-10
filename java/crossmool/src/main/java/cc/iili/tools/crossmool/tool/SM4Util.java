package cc.iili.tools.crossmool.tool;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cc.iili.tools.crossmool.util.Base64Util;
import cc.iili.tools.crossmool.util.HexUtil;

/**
 * SM4 国密对称加密工具类（GCM 模式） - 提供 Bouncy Castle 原生 API 和 JCA 标准 API 两种实现 -
 * 仅依赖 bcprov-jdkXXon，无其他第三方库
 * 
 * 支持 Hex 和 Base64 双编码格式，默认是 Hex，Hex 优先
 * 
 * Encrypt: use encrypt(String, String) to Hex, encrypt(String, String, true) to Base64
 * Decrypt: use decrypt(String, String) from Hex, decrypt(String, String, true) from Base64
 */
public class SM4Util {

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private static final String ALGORITHM_NAME = "SM4";
	private static final int KEY_SIZE_BITS = 128;
	private static final int KEY_SIZE_BYTES = KEY_SIZE_BITS / 8; // 16 bytes

	// GCM 推荐参数
	private static final int GCM_IV_LENGTH_BYTES = 12;  // 96 bits，推荐
	private static final int GCM_TAG_LENGTH_BITS = 128; // 认证标签长度，128 bits

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
	 * generate Base64 format SM4 key
	 */
	public static String generateKeyAsBase64() {
		return Base64Util.encodeBase64Str(generateKey());
	}

	/**
	 * generate SM4 key with format flag (default Hex)
	 */
	public static String generateKeyAsString(boolean toBase64) {
		if (toBase64) {
			return generateKeyAsBase64();
		}
		return generateKeyAsHex();
	}

	/**
	 * 从十六进制字符串解析密钥（忽略大小写） parse SM4 key from Hex string to byte array
	 */
	public static byte[] parseHexKey(String hexKey) {
		return HexUtil.decodeHexStr(hexKey);
	}

	/**
	 * 从 Base64 字符串解析密钥 parse SM4 key from Base64 string to byte array
	 */
	public static byte[] parseBase64Key(String base64Key) {
		return Base64Util.decodeBase64Str(base64Key);
	}

	/**
	 * 从字符串解析密钥，自动检测 Hex 或 Base64 格式 (Hex 优先)
	 */
	public static byte[] parseKey(String key) {
		if (key == null || key.isBlank()) {
			throw new IllegalArgumentException("key cannot be null or blank");
		}
		// Hex 优先
		if (HexUtil.isHexString(key)) {
			return HexUtil.decodeHexStr(key);
		} else if (Base64Util.isBase64String(key)) {
			return Base64Util.decodeBase64Str(key);
		} else {
			throw new IllegalArgumentException("key must be Hex string or Base64 string");
		}
	}

	/**
	 * 生成随机的 GCM IV（初始化向量）
	 */
	public static byte[] generateGcmIv() {
		byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
		new java.security.SecureRandom().nextBytes(iv);
		return iv;
	}

	// ========================
	// 2. Native Bouncy Castle API - GCM 模式
	// ========================

	/**
	 * GCM 加密（原生 API）- 返回格式：Base64(IV + 密文 (含认证标签))
	 *
	 * @param key   the 16-byte secret key
	 * @param input plaintext byte array
	 * @return Base64 编码的 IV+ 密文
	 */
	public static String encryptGcmNative(byte[] key, byte[] input) {
		return encryptGcmNative(key, input, null);
	}

	/**
	 * GCM 加密（原生 API）
	 *
	 * @param key   16 字节密钥
	 * @param input 明文
	 * @param iv    可选，若为 null 则自动生成随机 IV
	 * @return Base64 编码的 IV+ 密文
	 */
	public static String encryptGcmNative(byte[] key, byte[] input, byte[] iv) {
		validateKey(key);
		try {
			if (iv == null) {
				iv = generateGcmIv();
			}
			if (iv.length != GCM_IV_LENGTH_BYTES) {
				throw new IllegalArgumentException("GCM IV must be " + GCM_IV_LENGTH_BYTES + " bytes");
			}

			GCMModeCipher cipher = GCMBlockCipher.newInstance(new SM4Engine());
			AEADParameters parameters = new AEADParameters(
				new KeyParameter(key),
				GCM_TAG_LENGTH_BITS,
				iv
			);
			cipher.init(true, parameters);

			byte[] output = new byte[cipher.getOutputSize(input.length)];
			int len = cipher.processBytes(input, 0, input.length, output, 0);
			len += cipher.doFinal(output, len);

			byte[] cipherText = new byte[len];
			System.arraycopy(output, 0, cipherText, 0, len);

			byte[] result = new byte[iv.length + cipherText.length];
			System.arraycopy(iv, 0, result, 0, iv.length);
			System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

			return Base64.getEncoder().encodeToString(result);
		} catch (Exception e) {
			throw new RuntimeException("SM4 GCM native encryption failed", e);
		}
	}

	/**
	 * GCM 解密（原生 API）
	 *
	 * @param key         16 字节密钥
	 * @param encodedData Base64 编码的（IV + 密文）
	 * @return 解密后的明文字节数组
	 */
	public static byte[] decryptGcmNative(byte[] key, String encodedData) {
		validateKey(key);
		try {
			byte[] data = Base64.getDecoder().decode(encodedData);
			if (data.length < GCM_IV_LENGTH_BYTES) {
				throw new IllegalArgumentException("Invalid GCM data: too short");
			}

			byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
			byte[] cipherText = new byte[data.length - GCM_IV_LENGTH_BYTES];
			System.arraycopy(data, 0, iv, 0, GCM_IV_LENGTH_BYTES);
			System.arraycopy(data, GCM_IV_LENGTH_BYTES, cipherText, 0, cipherText.length);

			GCMModeCipher cipher = GCMBlockCipher.newInstance(new SM4Engine());
			AEADParameters parameters = new AEADParameters(
				new KeyParameter(key),
				GCM_TAG_LENGTH_BITS,
				iv
			);
			cipher.init(false, parameters);

			byte[] output = new byte[cipher.getOutputSize(cipherText.length)];
			int len = cipher.processBytes(cipherText, 0, cipherText.length, output, 0);
			len += cipher.doFinal(output, len);

			byte[] result = new byte[len];
			System.arraycopy(output, 0, result, 0, len);
			return result;
		} catch (Exception e) {
			throw new RuntimeException("SM4 GCM native decryption failed", e);
		}
	}

	/**
	 * GCM 解密返回字符串（原生 API）
	 */
	public static String decryptGcmNativeToString(byte[] key, String encodedData) {
		byte[] decrypted = decryptGcmNative(key, encodedData);
		return new String(decrypted, StandardCharsets.UTF_8);
	}

	// ========================
	// 3. JCA 标准 API - GCM 模式
	// ========================

	/**
	 * GCM 加密（JCA API）- 返回 Base64(IV + 密文)
	 */
	public static String encryptGcmJca(byte[] key, String plainText) {
		return encryptGcmJca(key, plainText, null);
	}

	/**
	 * GCM 加密（JCA API）
	 *
	 * @param key       16 字节密钥
	 * @param plainText 明文字符串
	 * @param iv        可选，若为 null 则自动生成随机 IV
	 * @return Base64 编码的 IV+ 密文
	 */
	public static String encryptGcmJca(byte[] key, String plainText, byte[] iv) {
		validateKey(key);
		try {
			if (iv == null) {
				iv = generateGcmIv();
			}
			if (iv.length != GCM_IV_LENGTH_BYTES) {
				throw new IllegalArgumentException("GCM IV must be " + GCM_IV_LENGTH_BYTES + " bytes");
			}

			Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", "BC");
			SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM_NAME);
			GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

			byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

			byte[] result = new byte[iv.length + cipherText.length];
			System.arraycopy(iv, 0, result, 0, iv.length);
			System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

			return Base64.getEncoder().encodeToString(result);
		} catch (Exception e) {
			throw new RuntimeException("SM4 GCM JCA encryption failed", e);
		}
	}

	/**
	 * GCM 解密（JCA API）
	 *
	 * @param key         16 字节密钥
	 * @param encodedData Base64 编码的（IV + 密文）
	 * @return 解密后的明文字符串
	 */
	public static String decryptGcmJca(byte[] key, String encodedData) {
		validateKey(key);
		try {
			byte[] data = Base64.getDecoder().decode(encodedData);
			if (data.length < GCM_IV_LENGTH_BYTES) {
				throw new IllegalArgumentException("Invalid GCM data: too short");
			}

			byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
			byte[] cipherText = new byte[data.length - GCM_IV_LENGTH_BYTES];
			System.arraycopy(data, 0, iv, 0, GCM_IV_LENGTH_BYTES);
			System.arraycopy(data, GCM_IV_LENGTH_BYTES, cipherText, 0, cipherText.length);

			Cipher cipher = Cipher.getInstance("SM4/GCM/NoPadding", "BC");
			SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM_NAME);
			GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
			cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

			byte[] decrypted = cipher.doFinal(cipherText);
			return new String(decrypted, StandardCharsets.UTF_8);
		} catch (Exception e) {
			throw new RuntimeException("SM4 GCM JCA decryption failed", e);
		}
	}

	// ========================
	// 4. 支持 Hex 和 Base64 双编码的加密解密方法 (参考 SM2Util 实现)
	// ========================

	/**
	 * GCM 加密，返回 Hex 格式 (IV + 密文 + Tag)
	 */
	public static String encryptToHex(byte[] key, byte[] plaintext) {
		return encrypt(key, plaintext, false);
	}

	/**
	 * GCM 加密，返回 Base64 格式 (IV + 密文 + Tag)
	 */
	public static String encryptToBase64(byte[] key, byte[] plaintext) {
		return encrypt(key, plaintext, true);
	}

	/**
	 * GCM 加密，支持 Hex 和 Base64 双编码输出
	 * 
	 * @param key       密钥字节数组
	 * @param plaintext 明文字节数组
	 * @param toBase64  true 返回 Base64 格式，false 返回 Hex 格式
	 * @return 加密结果 (Hex 或 Base64 格式)
	 */
	public static String encrypt(byte[] key, byte[] plaintext, boolean toBase64) {
		validateKey(key);
		try {
			byte[] iv = generateGcmIv();
			if (iv.length != GCM_IV_LENGTH_BYTES) {
				throw new IllegalArgumentException("GCM IV must be " + GCM_IV_LENGTH_BYTES + " bytes");
			}

			GCMModeCipher cipher = GCMBlockCipher.newInstance(new SM4Engine());
			AEADParameters parameters = new AEADParameters(
				new KeyParameter(key),
				GCM_TAG_LENGTH_BITS,
				iv
			);
			cipher.init(true, parameters);

			byte[] output = new byte[cipher.getOutputSize(plaintext.length)];
			int len = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
			len += cipher.doFinal(output, len);

			byte[] cipherText = new byte[len];
			System.arraycopy(output, 0, cipherText, 0, len);

			byte[] result = new byte[iv.length + cipherText.length];
			System.arraycopy(iv, 0, result, 0, iv.length);
			System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

			if (toBase64) {
				return Base64.getEncoder().encodeToString(result);
			}
			return HexUtil.encodeHexStr(result);
		} catch (Exception e) {
			throw new RuntimeException("SM4 GCM encryption failed", e);
		}
	}

	/**
	 * GCM 加密，支持 Hex 和 Base64 双编码输出 (默认 Hex)
	 * 
	 * @param key       密钥字节数组
	 * @param plaintext 明文字节数组
	 * @return 加密结果 (Hex 格式)
	 */
	public static String encrypt(byte[] key, byte[] plaintext) {
		return encrypt(key, plaintext, false);
	}

	/**
	 * GCM 加密，支持 Hex 和 Base64 双编码输出
	 * 
	 * @param key       密钥字符串 (Hex 或 Base64 格式)
	 * @param plaintext 明文字符串 (UTF-8 编码)
	 * @param toBase64  true 返回 Base64 格式，false 返回 Hex 格式
	 * @return 加密结果 (Hex 或 Base64 格式)
	 */
	public static String encrypt(String key, String plaintext, boolean toBase64) {
		byte[] keyBytes = parseKey(key);
		byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
		return encrypt(keyBytes, plaintextBytes, toBase64);
	}

	/**
	 * GCM 加密，支持 Hex 和 Base64 双编码输出 (默认 Hex)
	 * 
	 * @param key       密钥字符串 (Hex 或 Base64 格式)
	 * @param plaintext 明文字符串 (UTF-8 编码)
	 * @return 加密结果 (Hex 格式)
	 */
	public static String encrypt(String key, String plaintext) {
		return encrypt(key, plaintext, false);
	}

	/**
	 * GCM 解密，支持 Hex 和 Base64 双编码输入
	 * 
	 * @param key         密钥字节数组
	 * @param ciphertext  密文字符串 (Hex 或 Base64 格式，自动检测)
	 * @return 解密后的明文字节数组
	 */
	public static byte[] decryptToBytes(byte[] key, String ciphertext) {
		validateKey(key);
		byte[] data;
		// 自动检测 Hex 或 Base64 格式 (Hex 优先)
		if (HexUtil.isHexString(ciphertext)) {
			data = HexUtil.decodeHexStr(ciphertext);
		} else if (Base64Util.isBase64String(ciphertext)) {
			data = Base64Util.decodeBase64Str(ciphertext);
		} else {
			throw new IllegalArgumentException("ciphertext must be Hex string or Base64 string");
		}

		try {
			if (data.length < GCM_IV_LENGTH_BYTES) {
				throw new IllegalArgumentException("Invalid GCM data: too short");
			}

			byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
			byte[] cipherText = new byte[data.length - GCM_IV_LENGTH_BYTES];
			System.arraycopy(data, 0, iv, 0, GCM_IV_LENGTH_BYTES);
			System.arraycopy(data, GCM_IV_LENGTH_BYTES, cipherText, 0, cipherText.length);

			GCMModeCipher cipher = GCMBlockCipher.newInstance(new SM4Engine());
			AEADParameters parameters = new AEADParameters(
				new KeyParameter(key),
				GCM_TAG_LENGTH_BITS,
				iv
			);
			cipher.init(false, parameters);

			byte[] output = new byte[cipher.getOutputSize(cipherText.length)];
			int len = cipher.processBytes(cipherText, 0, cipherText.length, output, 0);
			len += cipher.doFinal(output, len);

			byte[] result = new byte[len];
			System.arraycopy(output, 0, result, 0, len);
			return result;
		} catch (Exception e) {
			throw new RuntimeException("SM4 GCM decryption failed", e);
		}
	}

	/**
	 * GCM 解密，支持 Hex 和 Base64 双编码输入
	 * 
	 * @param key         密钥字节数组
	 * @param ciphertext  密文字符串 (Hex 或 Base64 格式，自动检测)
	 * @return 解密后的明文字符串 (UTF-8 编码)
	 */
	public static String decrypt(byte[] key, String ciphertext) {
		byte[] decrypted = decryptToBytes(key, ciphertext);
		return new String(decrypted, StandardCharsets.UTF_8);
	}

	/**
	 * GCM 解密，支持 Hex 和 Base64 双编码输入
	 * 
	 * @param key         密钥字符串 (Hex 或 Base64 格式)
	 * @param ciphertext  密文字符串 (Hex 或 Base64 格式，自动检测)
	 * @return 解密后的明文字符串 (UTF-8 编码)
	 */
	public static String decrypt(String key, String ciphertext) {
		byte[] keyBytes = parseKey(key);
		return decrypt(keyBytes, ciphertext);
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
		String plainText = "Hello, 這是国密 SM4 測試數據";
		String hexKey = generateKeyAsHex();
		String base64Key = generateKeyAsBase64();
		byte[] key = parseKey(hexKey);

		System.out.println("原文：" + plainText);
		System.out.println("密钥 (HEX): " + hexKey);
		System.out.println("密钥 (Base64): " + base64Key);

		// ========== GCM 模式测试 ==========
		System.out.println("\n========== GCM 模式 ==========");

		// 原生 API
		byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
		String encGcmNative = encryptGcmNative(key, plainBytes);
		String decGcmNative = decryptGcmNativeToString(key, encGcmNative);
		System.out.println("[Native API GCM]");
		System.out.println("  加密结果 (Base64): " + encGcmNative);
		System.out.println("  解密结果：" + decGcmNative);

		// JCA API
		String encGcmJca = encryptGcmJca(key, plainText);
		String decGcmJca = decryptGcmJca(key, encGcmJca);
		System.out.println("[JCA API GCM]");
		System.out.println("  加密结果 (Base64): " + encGcmJca);
		System.out.println("  解密结果：" + decGcmJca);

		// 验证
		assert plainText.equals(decGcmNative) && plainText.equals(decGcmJca);

		// ========== Hex 和 Base64 双编码测试 ==========
		System.out.println("\n========== Hex 和 Base64 双编码测试 ==========");

		// Hex 加密
		String encHex = encrypt(key, plainBytes, false);
		System.out.println("[Hex 加密]");
		System.out.println("  加密结果 (Hex): " + encHex);
		String decFromHex = decrypt(key, encHex);
		System.out.println("  解密结果：" + decFromHex);
		assert plainText.equals(decFromHex);

		// Base64 加密
		String encBase64 = encrypt(key, plainBytes, true);
		System.out.println("[Base64 加密]");
		System.out.println("  加密结果 (Base64): " + encBase64);
		String decFromBase64 = decrypt(key, encBase64);
		System.out.println("  解密结果：" + decFromBase64);
		assert plainText.equals(decFromBase64);

		// 字符串密钥测试
		System.out.println("\n[字符串密钥测试]");
		String encHexStr = encrypt(hexKey, plainText, false);
		System.out.println("  Hex 密钥加密 (Hex 输出): " + encHexStr);
		String decHexStr = decrypt(hexKey, encHexStr);
		System.out.println("  解密结果：" + decHexStr);
		assert plainText.equals(decHexStr);

		String encBase64Str = encrypt(base64Key, plainText, true);
		System.out.println("  Base64 密钥加密 (Base64 输出): " + encBase64Str);
		String decBase64Str = decrypt(base64Key, encBase64Str);
		System.out.println("  解密结果：" + decBase64Str);
		assert plainText.equals(decBase64Str);

		// ========== GCM 防篡改测试 ==========
		System.out.println("\n========== GCM 防篡改测试 ==========");
		String tampered = encGcmJca.substring(0, encGcmJca.length() - 2) + "XX";
		try {
			String hacked = decryptGcmJca(key, tampered);
			System.out.println("❌ 篡改后仍能解密：" + hacked);
		} catch (Exception e) {
			System.out.println("✅ 篡改后解密失败（认证失败，GCM 自动检测到篡改）: " + e.getMessage());
		}

		System.out.println("\n✅ GCM 测试通过");
	}
}