package cc.iili.tools.crossmool.samples;

import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.SM2Util;

public class SM2Sample {
	
	/**
	 * Complete sample of SM2 encryption/decryption, signing/verification, and encrypt-then-sign.
	 * Usage steps:
	 * 1. Prepare a Maven project;
	 * 2. Add dependency cc.iili.tools:crossmool in pom.xml;
	 * 3. Run this sample as a Java Application.
	 */
	public static void main(String[] args) {
		/************** original content ***********/
		String originalContent = "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。";
		System.out.println("OriginalContent:::"+originalContent);

		/************** generate two key pairs: the 1st for encryption, the 2nd for signing ***********/
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
		
		/************** encrypt-then-sign, then verify-then-decrypt ***********/
		CiphertextSignaturePair encryptSign = SM2Util.encryptSign(originalContent, publicKeyHex, privateKeyHex2);
		String ciphertext = encryptSign.getCiphertext();
		String signature = encryptSign.getSignature();
		System.out.println("CipherText:::" + ciphertext);
		System.out.println("Signature:::"+signature);
		
		String verifyDecrypt = SM2Util.verifyDecrypt(encryptSign, publicKeyHex2, privateKeyHex);
		System.out.println("VerifyDecrypt:::" + verifyDecrypt);
		
		boolean equals = originalContent.equals(verifyDecrypt);
		System.out.println("WhetherVerifyDecryptEqualsOriginalContent:::"+equals);

		/************** encryption and decryption **************/
		String encryptedContent = SM2Util.encrypt(originalContent, publicKeyHex);
		System.out.println("EncryptedContent:::"+encryptedContent);
		String decryptedContent = SM2Util.decrypt(encryptedContent, privateKeyHex);
		System.out.println("DecryptedContent:::"+decryptedContent);
		boolean equals2 = originalContent.equals(decryptedContent);
		System.out.println("WhetherDecryptEqualsOriginalContent:::"+equals2);

		/************** signing and verification **************/
		String contentSignature = SM2Util.sign(originalContent, privateKeyHex2);
		System.out.println("ContentSignature:::"+contentSignature);
		boolean verify = SM2Util.verify(originalContent, publicKeyHex2, contentSignature);
		System.out.println("WhetherVerifyEqualsOriginalContent:::"+verify);

	}
	

}
