using System;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;

class Program
{
	static void Main(string[] args)
	{
		if (args.Length == 3)
		{
			// 命令行模式：encryptSign <message> <publicKey> <privateKey>
			var msg1 = args[0];
			var publicKey1 = args[1];
			var privateKey1 = args[2];
			
			var (ciphertextHex, signatureHex) = SM2Util.encryptSign(msg1, publicKey1, privateKey1);
			Console.WriteLine($"{ciphertextHex}\t{signatureHex}");
			return;
		}
		
		if (args.Length == 2)
		{
			// 命令行模式：encryptToHex <message> <publicKey>
			var msg2 = args[0];
			var publicKey2 = args[1];
			
			var ciphertextHex = SM2Util.encryptToHex(msg2, publicKey2);
			Console.WriteLine(ciphertextHex);
			return;
		}
		
		if (args.Length == 2 && args[0] == "sign")
		{
			// 命令行模式：sign <message> <privateKey>
			var msg3 = args[1];
			var privateKey3 = args[2];
			
			var signatureHex = SM2Util.sign(msg3, privateKey3);
			Console.WriteLine(signatureHex);
			return;
		}

		// 默认演示模式
		Console.WriteLine("SM2 KeyPair:");
		var kpJson = SM2Util.generateKeyPair();
		Console.WriteLine(kpJson);

		// Parse JSON manually (simple demo) to extract keys
		var privHex = ExtractJson(kpJson, "privateKeyHex");
		var pubHex = ExtractJson(kpJson, "publicKeyHex");

		var message = "你好，Crossmool!";
		Console.WriteLine($"Original: {message}");

		var sm2CipherB64 = SM2Util.encrypt(message, pubHex);
		Console.WriteLine($"SM2 Cipher (Base64): {sm2CipherB64}");
		var sm2Plain = SM2Util.decrypt(sm2CipherB64, privHex);
		Console.WriteLine($"SM2 Decrypt: {sm2Plain}");

		var sm2CipherHex = SM2Util.encryptToHex(message, pubHex);
		Console.WriteLine($"SM2 Cipher (Hex): {sm2CipherHex}");
		var sm2PlainHex = SM2Util.decryptFromHex(sm2CipherHex, privHex);
		Console.WriteLine($"SM2 Decrypt (Hex input): {sm2PlainHex}");

		var sm3Hex = SM3Util.digest(message);
		Console.WriteLine($"SM3 Digest (Hex): {sm3Hex}");
		var sm3B64 = SM3Util.digestBase64(message);
		Console.WriteLine($"SM3 Digest (Base64): {sm3B64}");

		// SM4-GCM with 16-byte key
		var sm4Key = "00112233445566778899aabbccddeeff"; // hex 16 bytes
		var sm4KeyBytes = EncodingUtils.FromHex(sm4Key);
		var sm4CipherB64 = SM4Util.EncryptGcmString(sm4KeyBytes, message);
		Console.WriteLine($"SM4-GCM Cipher (Base64): {sm4CipherB64}");
		var sm4Plain = SM4Util.DecryptGcmToString(sm4KeyBytes, sm4CipherB64);
		Console.WriteLine($"SM4-GCM Decrypt: {sm4Plain}");

		var sm4PlainBytes = EncodingUtils.Utf8GetBytes(message);
		var sm4CipherB64_2 = SM4Util.EncryptGcm(sm4KeyBytes, sm4PlainBytes);
		Console.WriteLine($"SM4-GCM Cipher bytes->Base64: {sm4CipherB64_2}");
		var sm4Decrypted = SM4Util.DecryptGcm(sm4KeyBytes, sm4CipherB64_2);
		Console.WriteLine($"SM4-GCM Decrypt (bytes): {EncodingUtils.Utf8GetString(sm4Decrypted)}");
	}

	static string ExtractJson(string json, string key)
	{
		var tag = $"\"{key}\":\"";
		var idx = json.IndexOf(tag, StringComparison.Ordinal);
		if (idx < 0) return string.Empty;
		idx += tag.Length;
		var end = json.IndexOf('"', idx);
		if (end < 0) end = json.Length;
		return json.Substring(idx, end - idx);
	}
}
