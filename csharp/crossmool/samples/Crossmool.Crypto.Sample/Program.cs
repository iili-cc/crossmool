using System;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;

class Program
{
	static void Main()
	{
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

		// SM4 with 16-byte key
		var sm4Key = "00112233445566778899aabbccddeeff"; // hex 16 bytes
		var sm4CipherB64 = SM4Util.encrypt(message, sm4Key);
		Console.WriteLine($"SM4 Cipher (Base64): {sm4CipherB64}");
		var sm4Plain = SM4Util.decrypt(sm4CipherB64, sm4Key);
		Console.WriteLine($"SM4 Decrypt: {sm4Plain}");

		var sm4CipherHex = SM4Util.encryptToHex(message, sm4Key);
		Console.WriteLine($"SM4 Cipher (Hex): {sm4CipherHex}");
		var sm4PlainHex = SM4Util.decryptFromHex(sm4CipherHex, sm4Key);
		Console.WriteLine($"SM4 Decrypt (Hex input): {sm4PlainHex}");
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
