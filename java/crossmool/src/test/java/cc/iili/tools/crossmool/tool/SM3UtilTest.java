package cc.iili.tools.crossmool.tool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import cc.iili.tools.crossmool.constant.SM3Constant;

@SuppressWarnings("deprecation")
class SM3UtilTest {

	@Test
	void testGenerateHmacKeyToStr() {
		String hmacKeyHex = SM3Util.generateHmacKeyToStr();
		String hmacKeyBase64 = SM3Util.generateHmacKeyToStr(32, true);
		assertNotNull(hmacKeyHex);
		assertNotNull(hmacKeyBase64);
		// 32-byte key -> 64 Hex characters
		assertEquals(64, hmacKeyHex.length());
	}

	@Test
	void testDigest() {
		String sm3TestString = SM3Constant.SM3_TEST_STRING;
		String hmacKeyBase64 = SM3Constant.HMAC_KEY_BASE64;

		String digestToStr = SM3Util.digestToStr(sm3TestString);
		// SM3 digest is fixed 32 bytes -> 64 Hex characters
		assertEquals(64, digestToStr.length());

		String hmacToStr = SM3Util.hmacToStr(sm3TestString, hmacKeyBase64);
		assertEquals(64, hmacToStr.length());

		boolean hmacVerify = SM3Util.hmacVerify(sm3TestString, hmacKeyBase64, hmacToStr);
		assertTrue(hmacVerify);

		// Verification should fail after tampering
		String tampered = hmacToStr.substring(0, 62) + "ff";
		assertFalse(SM3Util.hmacVerify(sm3TestString, hmacKeyBase64, tampered));
	}

}
