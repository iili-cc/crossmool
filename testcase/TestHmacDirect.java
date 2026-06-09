package testcase;

import cc.iili.tools.crossmool.tool.SM3Util;

public class TestHmacDirect {
    public static void main(String[] args) {
        String hmacKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        // 测试 "abc"
        String content = "abc";
        String hmacHex = SM3Util.hmacToStr(hmacKeyHex, content);
        System.out.println("Content: " + content);
        System.out.println("HMAC-SM3: " + hmacHex);
        System.out.println("HMAC length: " + hmacHex.length());
        
        // 测试 "Hello, Crossmool!"
        String content2 = "Hello, Crossmool!";
        String hmacHex2 = SM3Util.hmacToStr(hmacKeyHex, content2);
        System.out.println("\nContent: " + content2);
        System.out.println("HMAC-SM3: " + hmacHex2);
        System.out.println("HMAC length: " + hmacHex2.length());
    }
}