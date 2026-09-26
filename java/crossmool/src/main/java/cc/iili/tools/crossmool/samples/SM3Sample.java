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

        /**
         *  SM3 Hash: 54e020abea7ebe39b25e768541f00f750b7784f0ce29b7dd71fdd2b8761f9773
            SM3 Hash (Hex): 54e020abea7ebe39b25e768541f00f750b7784f0ce29b7dd71fdd2b8761f9773
            Whether Hash Equals Hex: true
         */
        String hmacKey = SM3Util.generateHmacKeyToStr();
        System.out.println("HMAC Key: " + hmacKey);
        String hmacValue = SM3Util.hmacToStr(input, hmacKey);
        System.out.println("HMAC Value: " + hmacValue);

        String hmacValue2 = SM3Util.hmacToStr(input, hmacKey);
        System.out.println("HMAC Value 2: " + hmacValue2);

        boolean hmacEquals = hmacValue.equals(hmacValue2);
        System.out.println("Whether HMAC Values Equal: " + hmacEquals);

        /**
         *  HMAC Key: b06321a31c05c63c19f0b701ab0c21d2956149119c3d8f7f18ac86d6a1b21656
            HMAC Value: 7c3abc43d27795450a1624458ee0c844a4d51a057a36d5dc1dc9710b19f82aab
            HMAC Value 2: 7c3abc43d27795450a1624458ee0c844a4d51a057a36d5dc1dc9710b19f82aab
            Whether HMAC Values Equal: true
         */
    }
}
