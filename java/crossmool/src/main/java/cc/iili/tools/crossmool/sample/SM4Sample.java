package cc.iili.tools.crossmool.sample;

import cc.iili.tools.crossmool.tool.SM4Util;

public class SM4Sample {

	/**
	 * 
	 * @param args
	 * 
	 * 1. Prepare a Maven Project;
	 * 2. install & add dependency to pom.xml
	 * 3. Execute this Sample(Java Application mode)
	 * 
	 * 
	 * 
	 * 
	 */
	public static void main(String[] args) {
		/**************the original content  ***********/
		String originalContent = "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。";
		System.out.println("OriginalContent:::" + originalContent);

		/**************generate SM4 key (Hex format)  ***********/
		String hexKey = SM4Util.generateKeyAsHex();
		System.out.println("SM4 Hex Key:::" + hexKey);

		/**************generate SM4 key (Base64 format)  ***********/
		String base64Key = SM4Util.generateKeyAsBase64();
		System.out.println("SM4 Base64 Key:::" + base64Key);

		/**************test encrypt & decrypt with Hex key (default Hex output)  ***********/
		String encryptedHex = SM4Util.encrypt(hexKey, originalContent);
		System.out.println("Encrypted (Hex):::" + encryptedHex);

		String decryptedHex = SM4Util.decrypt(hexKey, encryptedHex);
		System.out.println("Decrypted (Hex):::" + decryptedHex);

		boolean equalsHex = originalContent.equals(decryptedHex);
		System.out.println("WhetherDecryptEqualsOriginalContent (Hex):::" + equalsHex);

		/**************test encrypt & decrypt with Base64 key (Base64 output)  ***********/
		String encryptedBase64 = SM4Util.encrypt(base64Key, originalContent, true);
		System.out.println("Encrypted (Base64):::" + encryptedBase64);

		String decryptedBase64 = SM4Util.decrypt(base64Key, encryptedBase64);
		System.out.println("Decrypted (Base64):::" + decryptedBase64);

		boolean equalsBase64 = originalContent.equals(decryptedBase64);
		System.out.println("WhetherDecryptEqualsOriginalContent (Base64):::" + equalsBase64);

		/**************test GCM anti-tampering  ***********/
		String tampered = encryptedHex.substring(0, encryptedHex.length() - 2) + "XX";
		try {
			String hacked = SM4Util.decrypt(hexKey, tampered);
			System.out.println("Tampered decrypted:::" + hacked);
		} catch (Exception e) {
			System.out.println("GCM detected tampering, decryption failed:::" + e.getMessage());
		}

		/***
		 *  OriginalContent:::今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
			SM4 Hex Key:::e53aca738efe48d3f3ea1def683e4a74
			SM4 Base64 Key:::GHGgGjAovyQkb5blYcuH0g==
			Encrypted (Hex):::029bbb83cacb99ccc29eeb76a6cf69b65b94637aab1d978d20e6faeb7349d87489eb6921107a80d4add216e0fbd109f6ab7628d92a35e23241ae6e463e426ffffdb91f38eff15f3045e93c56415e4b88cf8be942c3a4eb8588dfb89b64075f0a9775eb8516bfa318cc30eb0f7316949b2edf6c74839b402e95c20df76422a147dd4a95090523747ea26871ab8fa0c58bfc286ffde59b6fb7ca18611cd3e60e9772f4df6f739e1121d54009f3c12df1d540b4b1ec1328a3098ae8a8e21c4079578a3a89842d6d9d1771c37032a48c99cdb56ad4000a00c6df115a2c32c0e14e348dfa71c3f0b38b197d4d4061d992f0ee68202e620a157f299fe1e86704558c816e8243134fe6554b647cdcdd05e3f6de4e301f678d5cbc34df4387bc6aa889c12fed6f80bf5a7a354aea43a1e1390d205e3ab2d3c241fb479d698a3f58e034580190148c21092678131b4418b24ed8978e929999233c9c036cd1a50cdcbce560d4214322c08c5a3b70d0d4f92a543f1b02c2d2514d0fdf27919be5218a28cdeac1107752987cb28238f7a627a58b9860738f8abccc3445b1c67434879aab63b77c97a81cae4a51fda98fab5e768267ca2f0004e2371d7d2cb05478c1eaa5168259c5ae0d0acb175b638ff8
			Decrypted (Hex):::今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
			WhetherDecryptEqualsOriginalContent (Hex):::true
			Encrypted (Base64):::ZXh44zJhig8kgzhh0xkmScBeYGGxXmsBkq05ErwhRRw19K5QsQxkL7znvy2nBMARBtrMQarp04sVNj2oQ9/kKRCz6fVHtBcc7Zt34PiMPMubU3QPfhJIOTUvR9ObDooTYopQh616Ml+QlfII/3WMi0u/FwlmPLaWNL5qaQI8OfF43uXY87UL0dzmY79SSEM8FwduKJJm69kqI+c8Lrsxev+UufauIgBb0nYgyJKD6SJMfUCspP11EE5YKNpuSImdueOCUOIhGwsHksI5wgICmjg6SCnX8osoVKpnrH6EvwoNsnPau+Un/ZQdK5MnMfDLsldaivCwrL0GVqOrWP3ULBLfu3JXIy+8vq16M9/YEDtZLS6RuTY81dlZ+Lv3Kf2XGxKLWnm3vgtOBm8tPq5gMgin0Ede7den8LZwm2n1zsJ8oOmyL1YdPj844+J+NDu72pSj0qlZ11qr/T4lmQYvOGgFv1OdIln1ZzFTmdbUarJnwzKb6A7u9zQTTaDEh9qLYUQ1XrjJm1xBzryyA94GO3OvXCuCuJ2Y3KnEuc5IrK8HKsxdodAsx+M0EyI+DoewSkTM1D5fExYS5DRz7axX33fuNTwV/zOZ8klB
			Decrypted (Base64):::今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
			WhetherDecryptEqualsOriginalContent (Base64):::true
			GCM detected tampering, decryption failed:::ciphertext must be Hex string or Base64 string
		 */
	}

}
