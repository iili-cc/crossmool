package cc.iili.tools.crossmool.samples;

import cc.iili.tools.crossmool.tool.SM3Util;

public class SM3Sample {
    public static void main(String[] args) {
        String input = "在这个全球化时代，無論身處何地，learning and growth are always the keys to a fulfilling life.";
        String hash = SM3Util.digestToStr(input);
        System.out.println("SM3 Hash: " + hash);

        String hashHex = SM3Util.digestToStr(input, false);
        System.out.println("SM3 Hash (Hex): " + hashHex);

        boolean equals = hash.equals(hashHex);
        System.out.println("Whether Hash Equals Hex: " + equals);

        String hmacKey = SM3Util.generateHmacKeyToStr();
        System.out.println("HMAC Key: " + hmacKey);
        String hmacValue = SM3Util.hmacToStr(input, hmacKey);
        System.out.println("HMAC Value: " + hmacValue);

        String hmacValue2 = SM3Util.hmacToStr(input, hmacKey);
        System.out.println("HMAC Value 2: " + hmacValue2);

        boolean hmacEquals = hmacValue.equals(hmacValue2);
        System.out.println("Whether HMAC Values Equal: " + hmacEquals);
    }
}
