
package cc.iili.tools.crossmool.test;
import cc.iili.tools.crossmool.tool.SM4Util;
public class SM4JavaToGoTest {
    public static void main(String[] args) {
        String key = "0123456789abcdeffedcba9876543210";
        String plain = "Hello SM4";
        
        // Hex º”√‹
        String encHex = SM4Util.encrypt(key, plain, false);
        System.out.println("JAVA_SM4_HEX_KEY=" + key);
        System.out.println("JAVA_SM4_HEX_PLAIN=" + plain);
        System.out.println("JAVA_SM4_HEX_CIPHER=" + encHex);
        
        // Base64 º”√‹
        String encBase64 = SM4Util.encrypt(key, plain, true);
        System.out.println("JAVA_SM4_B64_CIPHER=" + encBase64);
    }
}
