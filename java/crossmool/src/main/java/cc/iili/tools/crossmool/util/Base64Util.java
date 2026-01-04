package cc.iili.tools.crossmool.util;

import java.util.Base64;

public class Base64Util {
	
	public static final boolean isBase64String(String str) {
		if (str == null || str.length() == 0) {
			return false;
		}
		// 长度必须是4的倍数（Base64规范）
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
