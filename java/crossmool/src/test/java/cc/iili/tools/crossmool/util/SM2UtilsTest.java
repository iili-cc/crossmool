package cc.iili.tools.crossmool.util;

import org.junit.jupiter.api.Test;

class SM2UtilsTest {

    @Test
    void testGenerateKeyPairBase64() {
        SM2Utils.generateKeyPairBase64();
    }
    @Test
    void testGenerateKeyPairBHex() {
        SM2Utils.generateKeyPairHex();
    }

}
