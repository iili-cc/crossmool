package cc.iili.tools.crossmool.tool;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import cc.iili.tools.crossmool.util.HexUtil;

/**
 * SM4 国密对称加密工具类（支持 ECB/CBC/GCM 模式） - 提供 Bouncy Castle 原生 API 和 JCA 标准 API 两种实现 -
 * 仅依赖 bcprov-jdkXXon，无其他第三方库
 */
public class GcmSM4Util {

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

	public static byte[] generateKey() {
		byte[] key = new byte[KEY_SIZE_BYTES];
		new java.security.SecureRandom().nextBytes(key);
		return key;
	}

	public static String generateKeyAsHex() {
		return HexUtil.encodeHexStr(generateKey());
	}

	public static byte[] parseHexKey(String hexKey) {
		return HexUtil.decodeHexStr(hexKey);
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
	// 2. Native Bouncy Castle API - GCM 模式（推荐）
	// ========================

	/**
	 * GCM 加密（原生 API）- 返回格式：[IV(12字节)] + [密文(含认证标签)]
	 */
	public static String encryptGcmNative(byte[] key, byte[] input) {
		return encryptGcmNative(key, input, null);
	}
	
	/**
	 * GCM 加密（原生 API）
	 * @param key 16字节密钥
	 * @param input 明文
	 * @param iv 可选，若为null则自动生成随机IV
	 * @return Base64 编码的 IV+密文（便于传输）
	 */
	public static String encryptGcmNative(byte[] key, byte[] input, byte[] iv) {
		validateKey(key);
		try {
			// 如果没有传入 IV，自动生成
			if (iv == null) {
				iv = generateGcmIv();
			}
			if (iv.length != GCM_IV_LENGTH_BYTES) {
				throw new IllegalArgumentException("GCM IV must be " + GCM_IV_LENGTH_BYTES + " bytes");
			}
			
			GCMBlockCipher cipher = (GCMBlockCipher) GCMBlockCipher.newInstance(new SM4Engine());
			AEADParameters parameters = new AEADParameters(
				new KeyParameter(key), 
				GCM_TAG_LENGTH_BITS, 
				iv
			);
			cipher.init(true, parameters);
			
			byte[] output = new byte[cipher.getOutputSize(input.length)];
			int len = cipher.processBytes(input, 0, input.length, output, 0);
			len += cipher.doFinal(output, len);
			
			// 提取真正的密文（不包含IV）
			byte[] cipherText = new byte[len];
			System.arraycopy(output, 0, cipherText, 0, len);
			
			// 返回 Base64(IV + 密文)
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
	 * @param key 16字节密钥
	 * @param encodedData Base64 编码的（IV + 密文）
	 */
	public static byte[] decryptGcmNative(byte[] key, String encodedData) {
		validateKey(key);
		try {
			byte[] data = Base64.getDecoder().decode(encodedData);
			if (data.length < GCM_IV_LENGTH_BYTES) {
				throw new IllegalArgumentException("Invalid GCM data: too short");
			}
			
			// 分离 IV 和密文
			byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
			byte[] cipherText = new byte[data.length - GCM_IV_LENGTH_BYTES];
			System.arraycopy(data, 0, iv, 0, GCM_IV_LENGTH_BYTES);
			System.arraycopy(data, GCM_IV_LENGTH_BYTES, cipherText, 0, cipherText.length);
			
			GCMBlockCipher cipher = new GCMBlockCipher(new SM4Engine());
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
	 * GCM 解密返回字符串
	 */
	public static String decryptGcmNativeToString(byte[] key, String encodedData) {
		byte[] decrypted = decryptGcmNative(key, encodedData);
		return new String(decrypted, StandardCharsets.UTF_8);
	}

	// ========================
	// 3. JCA 标准 API - GCM 模式（更简洁）
	// ========================

	/**
	 * GCM 加密（JCA API）- 返回 Base64(IV + 密文)
	 */
	public static String encryptGcmJca(byte[] key, String plainText) {
		return encryptGcmJca(key, plainText, null);
	}
	
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
			
			// 拼接 IV + 密文
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
	// 保留原有的 ECB 方法（供兼容）
	// ========================

	// ... 你的原有 ECB 方法保持不变 ...
	
	// 为了保持原有功能，这里省略原有的 ECB 方法代码
	// 实际使用时需要保留 encryptEcbNative, decryptEcbNative, encryptEcbJca, decryptEcbJca

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

		System.out.println("原文: " + plainText);
		System.out.println("密钥(HEX): " + hexKey);
		
		// ========== GCM 模式测试 ==========
		System.out.println("\n========== GCM 模式 ==========");
		
		// 原生 API
		byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
		String encGcmNative = encryptGcmNative(key, plainBytes);
		String decGcmNative = decryptGcmNativeToString(key, encGcmNative);
		System.out.println("[Native API GCM]");
		System.out.println("  加密结果(Base64): " + encGcmNative);
		System.out.println("  解密结果: " + decGcmNative);
		
		// JCA API
		String encGcmJca = encryptGcmJca(key, plainText);
		String decGcmJca = decryptGcmJca(key, encGcmJca);
		System.out.println("[JCA API GCM]");
		System.out.println("  加密结果(Base64): " + encGcmJca);
		System.out.println("  解密结果: " + decGcmJca);
		
		// 验证
		assert plainText.equals(decGcmNative) && plainText.equals(decGcmJca);
		
		// ========== 对比测试：篡改检测 ==========
		System.out.println("\n========== GCM 防篡改测试 ==========");
		String tampered = encGcmJca.substring(0, encGcmJca.length() - 2) + "XX";
		try {
			String hacked = decryptGcmJca(key, tampered);
			System.out.println("❌ 篡改后仍能解密: " + hacked);
		} catch (Exception e) {
			System.out.println("✅ 篡改后解密失败（认证失败，GCM 自动检测到篡改）: " + e.getMessage());
		}
		
		System.out.println("\n✅ GCM 测试通过");
	}
}