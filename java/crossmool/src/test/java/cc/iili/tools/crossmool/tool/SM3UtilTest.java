package cc.iili.tools.crossmool.tool;

import org.junit.jupiter.api.Test;

import cc.iili.tools.crossmool.constant.SM3Constant;

class SM3UtilTest {

	@Test
	void testGenerateHmacKeyToStr() {
		String hmacKeyToStr = SM3Util.generateHmacKeyToStr();
		System.out.println("hmacKeyToStr is :::" + hmacKeyToStr);
		String hmacKeyToStr2 = SM3Util.generateHmacKeyToStr(32, true);
		System.out.println("hmacKeyToStr2 is :::" + hmacKeyToStr2);

	}

	@SuppressWarnings("deprecation")
	@Test
	void testDigest() {
		String sm3TestString = SM3Constant.SM3_TEST_STRING;
		String hmacKeyBase64 = SM3Constant.HMAC_KEY_BASE64;

		String digestToStr = SM3Util.digestToStr(sm3TestString);
		System.out.println("digestToStr:::" + digestToStr);

		String hmacToStr = SM3Util.hmacToStr(sm3TestString, hmacKeyBase64);
		System.out.println("hmacToStr:::" + hmacToStr);

		boolean hmacVerify = SM3Util.hmacVerify(sm3TestString, hmacKeyBase64, hmacToStr);
		System.out.println("hmacVerify:::" + hmacVerify);

	}

}
