package cc.iili.tools.crossmool.util;

import org.bouncycastle.util.encoders.Hex;

public class HexUtil {
    
    public static final boolean isHexString(String str) {
        // 最常用规则：纯十六进制数字，允许大小写A-F
        return str != null && str.matches("^[0-9a-fA-F]+$");
        // 如果需要支持 "0x" 或 "0X" 前缀，可使用：
        // return str != null && str.matches("^(0[xX])?[0-9a-fA-F]+$");
    }
    
    public static String encodeHexStr(byte[] data) {
        return Hex.toHexString(data);
    }
    
    public static byte[] decodeHexStr(String hex) {
        return Hex.decodeStrict(hex);
    }

}
