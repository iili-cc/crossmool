package cc.iili.tools.crossmool.util;

import org.bouncycastle.util.encoders.Hex;

public class HexUtil {
    
    /**
     * Check whether the string is a valid hexadecimal representation.
     * Note: under Hex/Base64 auto-detection (Hex first), a Base64 string that happens to
     * consist entirely of [0-9a-fA-F] and has an even length will be misjudged as Hex.
     * This is an inherent ambiguity of auto-detection; callers should be aware of it.
     */
    public static final boolean isHexString(String str) {
        // Most common rule: pure hexadecimal digits, allowing upper/lowercase A-F
        // Note: a hex string must have an even number of characters (each byte is two hex chars)
        return str != null && str.length() % 2 == 0 && str.matches("^[0-9a-fA-F]+$");
        // If you need to support "0x" or "0X" prefix, use:
        // return str != null && str.length() % 2 == 0 && str.matches("^(0[xX])?[0-9a-fA-F]+$");
    }
    
    public static String encodeHexStr(byte[] data) {
        return Hex.toHexString(data);
    }
    
    public static byte[] decodeHexStr(String hex) {
        return Hex.decodeStrict(hex);
    }

}
