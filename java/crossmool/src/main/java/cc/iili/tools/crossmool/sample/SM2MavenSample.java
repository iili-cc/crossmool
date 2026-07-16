package cc.iili.tools.crossmool.sample;

import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;

public class SM2MavenSample {
	
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
		System.out.println("OriginalContent:::"+originalContent);
		/**************generate 2 key pairs, the 1st is for crypto, the 2nd is for signature ***********/
		SerialKeyPair keyPairHex = SM2Util.generateKeyPairHex();
		String privateKeyHex = keyPairHex.getPrivateKey();
		String publicKeyHex = keyPairHex.getPublicKey();
		System.out.println("privateKeyHex-1:::" + privateKeyHex);
		System.out.println("publicKeyHex-1:::" + publicKeyHex);
		
		SerialKeyPair keyPairHex2 = SM2Util.generateKeyPairHex();
		String privateKeyHex2 = keyPairHex2.getPrivateKey();
		String publicKeyHex2 = keyPairHex2.getPublicKey();
		System.out.println("privateKeyHex-2:::" + privateKeyHex2);
		System.out.println("publicKeyHex-2:::" + publicKeyHex2);
		
		/**************test the-encrypt-then-sign & the-verify-then-decrypt  ***********/
		CiphertextSignaturePair encryptSign = SM2Util.encryptSign(originalContent, publicKeyHex, privateKeyHex2);
		String ciphertext = encryptSign.getCiphertext();
		String signature = encryptSign.getSignature();
		System.out.println("CipherText:::" + ciphertext);
		System.out.println("Signature:::"+signature);
		
		String verifyDecrypt = SM2Util.verifyDecrypt(encryptSign, publicKeyHex2, privateKeyHex);
		System.out.println("VerifyDecrypt:::" + verifyDecrypt);
		
		boolean equals = originalContent.equals(verifyDecrypt);
		System.out.println("WhetherVerifyDecryptEqualsOriginalContent:::"+equals);
		
		/***
		 * This OriginalContent includes English + 简体中文 + 繁體中文
		 *  OriginalContent:::今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
		privateKeyHex-1:::308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104200ea7176f915eb7ab07b372e5a11b1e4479748dbfdf59ced0c1462502bdf9056fa00a06082a811ccf5501822da14403420004fd4ce75444a207ba125fd8425308b107c96f241b3c2e3a3d57576d96361d0ce363335accf92ea2a914457541e4a32d5acb6b4d68d4663a61d83c1d8a4f087b39
		publicKeyHex-1:::3059301306072a8648ce3d020106082a811ccf5501822d03420004fd4ce75444a207ba125fd8425308b107c96f241b3c2e3a3d57576d96361d0ce363335accf92ea2a914457541e4a32d5acb6b4d68d4663a61d83c1d8a4f087b39
		privateKeyHex-2:::308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420a9a352ddc583af73f8117e3c8621e14da9ae43f5b0907895e53d344001e4de10a00a06082a811ccf5501822da14403420004c9fbc8fea252807bbd66ce7215ef7ed95ea286978150516dbde9401b619469324a28dd20b486b98882316dcf37d1b19f65a521137948f6b84b540af7f5a258c0
		publicKeyHex-2:::3059301306072a8648ce3d020106082a811ccf5501822d03420004c9fbc8fea252807bbd66ce7215ef7ed95ea286978150516dbde9401b619469324a28dd20b486b98882316dcf37d1b19f65a521137948f6b84b540af7f5a258c0
		CipherText:::04de0a436767a25d33af559da2665a4d52b33fdfb83c90c582c4d2b93749f5e616151fdd7087e2b40f9087f8ee97b823ac957448acb15778556279e88a56a2b515589985242f4ea8c3705262798d2ed63c7172dfb55c84184c4fa19c83ba2efc43f8c1ff1d5ff1d818c66762283c50d41f92e4f7877193427f72deca2ce00626e017a627e5da66c28a8f3f0cdc17853239290421ab247ce93e78802bc66fbfed0476e5e37965e56e110b507eb29c2dd4ec7ed22b6846e82eb498380774b5fbd9c40e2cdd248d84ed6b39d2ed4448914c6828f7fdfc0ca3f05fc20ea34892484a4a727e4dae36f00b5133fe34fd2bf693b5840d864a47fec089b02b1ddd473a043ae6a2e9118eb08cec112cb61415df1b405a844d3d1e5cb2f02bba68f746240a95010b2f0eda67a3faa7168592fe796b2b8f16d840e709971d49421ede0555881061472123e3ff7c116518a2e15d2940a19955ae006214f66b8770776599e62e675bcc7fa9a111d58bee05b154d5b229a6959cc816107b2d872e39a2a0f62aa34f3b3ca735804a8777b4b16d55158cbf0e2fe68943b8d1d0584bfcac24625145bf29317a68a77c5b28e505f6703bd1397f47aba17acc10b1ce0f75872658a9154ed4867f574f84fd088de5a0b52007eee981816173511672132ba25dfa82ea4b52fc506f26a26cda61d22ef0d7227e42899d4cd78acd70d07e6f02c9f9c1d0b71529d39bdcab728cab13280311cfbc3e
		Signature:::304502203f8eb7c6be71ea4e76f25e601fd3ef205372e7880aaef99eac0ceae1394c2bb002210092fd82848e15f7405a1f311a049a84886666f144a61400e0df981dcf6261e11d
		VerifyDecrypt:::今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
		WhetherVerifyDecryptEqualsOriginalContent:::true
		 */
		/**************test the encrypt & decrypt **************/
		String encryptedContent = SM2Util.encrypt(originalContent, publicKeyHex);
		System.out.println("EncryptedContent:::"+encryptedContent);
		String decryptedContent = SM2Util.decrypt(encryptedContent, privateKeyHex);
		System.out.println("DecryptedContent:::"+decryptedContent);
		boolean equals2 = originalContent.equals(decryptedContent);
		System.out.println("WhetherDecryptEqualsOriginalContent:::"+equals2);

		/**
		 *  EncryptedContent:::04a4d61d06958d355ffaeea2629d106ffaacb519e7fdef0d6a1a53a752b1d407a09394860a7ee3745ec50c2f18d75b05d090d72becf60dc70a8400ce1ee74c86ffb90fb3eec89272caebfdfe285b61890837953bfeb482724625e2f179a58d6f38c58459e10bdb242c78e788a7dab6203a54e32dd189c619c1851ba43155e03c59f3254bfd4c91c1017682188634307cd83c0268d13552e62b5f5e6ab06cc19ed033bc62b6b3cf709989ddf8ba63f40f4b46d9f44075c1c107e2e0b2c6f85a4d79e67c888d3d88e61c70c8598b67c061d1bf5bc57938913308c7d1ee737f23c46c9403f88b3437e9802616c879aa8b062a13ce4a5b7477b440945be0c1c92cb392dd0116a9513621ebdc484042d5c76f8368ae799ffa6d2d3b606c849f5be057dc775746c8847e6d298076526f52d8be6852a4890104608d16c7338c916ee06aaa88fbfddce975da0c73e5a84567dce2c5bab264c22f56bd05454a8e4cbdbb725e7a76eff3a1dce49a364c8d815302b49b12e3cd5f1f94527f5e27ba516f5e7a891723b9b8e852031211b42bd17b5bfaa4eedeb1e858a739e0f7e0055a34c9eb2b401d9b1c6dc7b39728aed47081499691fd24a4f65141a16dffa05691c5afa4a2184d26e8d5ae5c5a597bc4d00da68a5613913b328e26574a732dc06b665ad0c298833e45afafffdd5be40c9a346a4acf80b8d7f8ddca083903823388806b6c7f189400fdeb1fc0a01f6f634d5c431c
			DecryptedContent:::今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
			WhetherDecryptEqualsOriginalContent:::true
		 */

		/**************test the sign & verify **************/
		String contentSignature = SM2Util.sign(originalContent, privateKeyHex2);
		System.out.println("ContentSignature:::"+contentSignature);
		boolean verify = SM2Util.verify(originalContent, publicKeyHex2, contentSignature);
		System.out.println("WhetherVerifyEqualsOriginalContent:::"+verify);
		/**
		 *  ContentSignature:::304402205779009f7375c4957c92177700bbd12935a6f6973529cbe3e1db830dd0b1bcfd02202e6ca0e3dbc24a48b691c9b8d3ad628650a615a4ea55e844f67abb4cc5f1a868
			WhetherVerifyEqualsOriginalContent:::true
		 */

	}
	

}
