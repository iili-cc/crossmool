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
 * SM4 (Chinese national standard) symmetric encryption utility (GCM mode).
 * Provides two implementations: Bouncy Castle native API and JCA standard API.
 * Depends only on bcprov-jdkXXon, no other third-party libraries.
 * 
 * Supports both Hex and Base64 encoding, Hex is the default and Hex is checked first.
 * 
 * Parameter order convention: the 1st parameter is the plaintext (encrypt) / ciphertext (decrypt),
 * the 2nd parameter is the key (password), remaining parameters follow at 3, 4, 5...
 * 
 * Encrypt: use encrypt(String plaintext, String key) to Hex, encrypt(String plaintext, String key, true) to Base64
 * Decrypt: use decrypt(String ciphertext, String key) auto-detect Hex/Base64
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

	// GCM recommended parameters
	private static final int GCM_IV_LENGTH_BYTES = 12;  // 96 bits, recommended
	private static final int GCM_TAG_LENGTH_BITS = 128; // authentication tag length, 128 bits

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
	 * parse SM4 key from Hex string to byte array (case-insensitive)
	 */
	public static byte[] parseHexKey(String hexKey) {
		return HexUtil.decodeHexStr(hexKey);
	}

	/**
	 * parse SM4 key from Base64 string to byte array
	 */
	public static byte[] parseBase64Key(String base64Key) {
		return Base64Util.decodeBase64Str(base64Key);
	}

	/**
	 * parse key from string, auto-detect Hex or Base64 format (Hex first)
	 */
	public static byte[] parseKey(String key) {
		if (key == null || key.isBlank()) {
			throw new IllegalArgumentException("key cannot be null or blank");
		}
		// Hex first
		if (HexUtil.isHexString(key)) {
			return HexUtil.decodeHexStr(key);
		} else if (Base64Util.isBase64String(key)) {
			return Base64Util.decodeBase64Str(key);
		} else {
			throw new IllegalArgumentException("key must be Hex string or Base64 string");
		}
	}

	/**
	 * generate a random GCM IV (initialization vector)
	 */
	public static byte[] generateGcmIv() {
		byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
		new java.security.SecureRandom().nextBytes(iv);
		return iv;
	}

	// ========================
	// 2. Native Bouncy Castle API - GCM mode
	// ========================

	/**
	 * GCM encryption (native API) - returns: Base64(IV + ciphertext (with authentication tag))
	 *
	 * @param input plaintext byte array
	 * @param key   the 16-byte secret key
	 * @return Base64-encoded IV + ciphertext
	 */
	public static String encryptGcmNative(byte[] input, byte[] key) {
		return encryptGcmNative(input, key, null);
	}

	/**
	 * GCM encryption (native API)
	 *
	 * @param input plaintext
	 * @param key   16-byte secret key
	 * @param iv    optional, a random IV is generated automatically if null
	 * @return Base64-encoded IV + ciphertext
	 */
	public static String encryptGcmNative(byte[] input, byte[] key, byte[] iv) {
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
	 * GCM decryption (native API)
	 *
	 * @param encodedData Base64-encoded (IV + ciphertext)
	 * @param key         16-byte secret key
	 * @return decrypted plaintext byte array
	 */
	public static byte[] decryptGcmNative(String encodedData, byte[] key) {
		validateKey(key);
		try {
			byte[] data = decodeCipherData(encodedData);
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
	 * GCM decryption returning string (native API)
	 */
	public static String decryptGcmNativeToString(String encodedData, byte[] key) {
		byte[] decrypted = decryptGcmNative(encodedData, key);
		return new String(decrypted, StandardCharsets.UTF_8);
	}

	// ========================
	// 3. JCA standard API - GCM mode
	// ========================

	/**
	 * GCM encryption (JCA API) - returns Base64(IV + ciphertext)
	 */
	public static String encryptGcmJca(String plainText, byte[] key) {
		return encryptGcmJca(plainText, key, null);
	}

	/**
	 * GCM encryption (JCA API)
	 *
	 * @param plainText plaintext string
	 * @param key       16-byte secret key
	 * @param iv        optional, a random IV is generated automatically if null
	 * @return Base64-encoded IV + ciphertext
	 */
	public static String encryptGcmJca(String plainText, byte[] key, byte[] iv) {
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
	 * GCM decryption (JCA API)
	 *
	 * @param encodedData Base64-encoded (IV + ciphertext)
	 * @param key         16-byte secret key
	 * @return decrypted plaintext string
	 */
	public static String decryptGcmJca(String encodedData, byte[] key) {
		validateKey(key);
		try {
			byte[] data = decodeCipherData(encodedData);
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
	// 4. Encrypt/decrypt methods supporting both Hex and Base64 encoding (refer to SM2Util)
	// ========================

	/**
	 * GCM encryption, returns Hex format (IV + ciphertext + tag)
	 */
	public static String encryptToHex(byte[] plaintext, byte[] key) {
		return encrypt(plaintext, key, false);
	}

	/**
	 * GCM encryption, returns Base64 format (IV + ciphertext + tag)
	 */
	public static String encryptToBase64(byte[] plaintext, byte[] key) {
		return encrypt(plaintext, key, true);
	}

	/**
	 * GCM encryption, supports both Hex and Base64 output
	 * 
	 * @param plaintext plaintext byte array
	 * @param key       key byte array
	 * @param toBase64  true returns Base64, false returns Hex
	 * @return encryption result (Hex or Base64 format)
	 */
	public static String encrypt(byte[] plaintext, byte[] key, boolean toBase64) {
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
	 * GCM encryption, supports both Hex and Base64 output (default Hex)
	 * 
	 * @param plaintext plaintext byte array
	 * @param key       key byte array
	 * @return encryption result (Hex format)
	 */
	public static String encrypt(byte[] plaintext, byte[] key) {
		return encrypt(plaintext, key, false);
	}

	/**
	 * GCM encryption, supports both Hex and Base64 output
	 * 
	 * @param plaintext plaintext string (UTF-8 encoded)
	 * @param key       key string (Hex or Base64 format)
	 * @param toBase64  true returns Base64, false returns Hex
	 * @return encryption result (Hex or Base64 format)
	 */
	public static String encrypt(String plaintext, String key, boolean toBase64) {
		byte[] keyBytes = parseKey(key);
		byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
		return encrypt(plaintextBytes, keyBytes, toBase64);
	}

	/**
	 * GCM encryption, supports both Hex and Base64 output (default Hex)
	 * 
	 * @param plaintext plaintext string (UTF-8 encoded)
	 * @param key       key string (Hex or Base64 format)
	 * @return encryption result (Hex format)
	 */
	public static String encrypt(String plaintext, String key) {
		return encrypt(plaintext, key, false);
	}

	/**
	 * GCM decryption, supports both Hex and Base64 input
	 * 
	 * @param ciphertext ciphertext string (Hex or Base64 format, auto-detected)
	 * @param key        key byte array
	 * @return decrypted plaintext byte array
	 */
	public static byte[] decryptToBytes(String ciphertext, byte[] key) {
		validateKey(key);
		byte[] data = decodeCipherData(ciphertext);

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
	 * GCM decryption, supports both Hex and Base64 input
	 * 
	 * @param ciphertext ciphertext string (Hex or Base64 format, auto-detected)
	 * @param key        key byte array
	 * @return decrypted plaintext string (UTF-8 encoded)
	 */
	public static String decrypt(String ciphertext, byte[] key) {
		byte[] decrypted = decryptToBytes(ciphertext, key);
		return new String(decrypted, StandardCharsets.UTF_8);
	}

	/**
	 * GCM decryption, supports both Hex and Base64 input
	 * 
	 * @param ciphertext ciphertext string (Hex or Base64 format, auto-detected)
	 * @param key        key string (Hex or Base64 format)
	 * @return decrypted plaintext string (UTF-8 encoded)
	 */
	public static String decrypt(String ciphertext, String key) {
		byte[] keyBytes = parseKey(key);
		return decrypt(ciphertext, keyBytes);
	}

	// ========================
	// helper method
	// ========================

	private static void validateKey(byte[] key) {
		if (key == null || key.length != KEY_SIZE_BYTES) {
			throw new IllegalArgumentException("SM4 key must be 16 bytes (128 bits)");
		}
	}

	/**
	 * Auto-detect and decode Hex or Base64 encoded ciphertext data (Hex first).
	 * Note: a Base64 string that happens to consist entirely of hexadecimal characters
	 * with an even length will be misjudged as Hex.
	 */
	private static byte[] decodeCipherData(String encodedData) {
		if (encodedData == null || encodedData.isBlank()) {
			throw new IllegalArgumentException("ciphertext cannot be null or blank");
		}
		if (HexUtil.isHexString(encodedData)) {
			return HexUtil.decodeHexStr(encodedData);
		} else if (Base64Util.isBase64String(encodedData)) {
			return Base64Util.decodeBase64Str(encodedData);
		} else {
			throw new IllegalArgumentException("ciphertext must be Hex string or Base64 string");
		}
	}
}
