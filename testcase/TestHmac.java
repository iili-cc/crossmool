package testcase;

import cc.iili.tools.crossmool.tool.SM3Util;
import java.util.Base64;

public class TestHmac {
    public static void main(String[] args) {
        String hmacKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        // 测试 "abc"
        String content = "abc";
        String contentB64 = Base64.getEncoder().encodeToString(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        
        System.out.println("Content: " + content);
        System.out.println("Content Base64: " + contentB64);
        
        String hmacHex = SM3Util.hmacToStr(hmacKeyHex, content);
        System.out.println("HMAC-SM3: " + hmacHex);
        System.out.println("HMAC length: " + hmacHex.length());
    }
}