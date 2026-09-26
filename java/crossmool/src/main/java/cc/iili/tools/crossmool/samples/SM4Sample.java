package cc.iili.tools.crossmool.samples;

import cc.iili.tools.crossmool.tool.SM4Util;

public class SM4Sample {

	/**
	 * Complete sample of SM4-GCM encryption/decryption (Hex/Base64 dual encoding + tamper verification).
	 * Usage steps:
	 * 1. Prepare a Maven project;
	 * 2. Add dependency cc.iili.tools:crossmool in pom.xml;
	 * 3. Run this sample as a Java Application.
	 */
	public static void main(String[] args) {
		/************** original content ***********/
		String originalContent = "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。";
		System.out.println("OriginalContent:::" + originalContent);

		/************** generate SM4 key (Hex format) ***********/
		String hexKey = SM4Util.generateKeyAsHex();
		System.out.println("SM4 Hex Key:::" + hexKey);

		/************** generate SM4 key (Base64 format) ***********/
		String base64Key = SM4Util.generateKeyAsBase64();
		System.out.println("SM4 Base64 Key:::" + base64Key);

		/************** Hex key encryption and decryption (default Hex output) ***********/
		String encryptedHex = SM4Util.encrypt(originalContent, hexKey);
		System.out.println("Encrypted (Hex):::" + encryptedHex);

		String decryptedHex = SM4Util.decrypt(encryptedHex, hexKey);
		System.out.println("Decrypted (Hex):::" + decryptedHex);

		boolean equalsHex = originalContent.equals(decryptedHex);
		System.out.println("WhetherDecryptEqualsOriginalContent (Hex):::" + equalsHex);

		/************** Base64 key encryption and decryption (Base64 output) ***********/
		String encryptedBase64 = SM4Util.encrypt(originalContent, base64Key, true);
		System.out.println("Encrypted (Base64):::" + encryptedBase64);

		String decryptedBase64 = SM4Util.decrypt(encryptedBase64, base64Key);
		System.out.println("Decrypted (Base64):::" + decryptedBase64);

		boolean equalsBase64 = originalContent.equals(decryptedBase64);
		System.out.println("WhetherDecryptEqualsOriginalContent (Base64):::" + equalsBase64);

		/************** GCM tamper verification ***********/
		String tampered = encryptedHex.substring(0, encryptedHex.length() - 2) + "XX";
		try {
			String hacked = SM4Util.decrypt(tampered, hexKey);
			System.out.println("Tampered decrypted:::" + hacked);
		} catch (Exception e) {
			System.out.println("GCM detected tampering, decryption failed:::" + e.getMessage());
		}
	}

}
