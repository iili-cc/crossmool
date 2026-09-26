package cc.iili.tools.crossmool.util;

import java.util.Base64;

public class Base64Util {
	
	/**
	 * Check whether the string is a valid Base64 representation.
	 * Note: under Hex/Base64 auto-detection (Hex first), a Base64 string that consists
	 * entirely of hexadecimal characters will be judged as Hex first.
	 * This is an inherent ambiguity of auto-detection; callers should be aware of it.
	 */
	public static final boolean isBase64String(String str) {
		if (str == null || str.length() == 0) {
			return false;
		}
		// Length must be a multiple of 4 (Base64 specification)
        if (str.length() % 4 != 0) {
            return false;
        }
        try {
            Base64.getDecoder().decode(str);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
	}
	
	public static String encodeBase64Str(byte[] data) {
		return Base64.getEncoder().encodeToString(data);
	}
	
	public static byte[] decodeBase64Str(String base64) {
		return Base64.getDecoder().decode(base64);
	}
	
}
