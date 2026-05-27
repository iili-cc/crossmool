using System;
using System.IO;
using System.Text;
using System.Text.Json;
using Crossmool.Crypto;

class Program
{
    static void Main()
    {
        try
        {
            // Test: encrypt a string containing \r, then decrypt and check bytes
            string testStr = "Special chars: \n\t\r\"'<>{}[]|\\^~`";
            byte[] testBytes = Encoding.UTF8.GetBytes(testStr);
            
            Console.WriteLine("Original string hex: " + BitConverter.ToString(testBytes).Replace("-", ""));
            Console.WriteLine("Original has \\r (0D): " + (Array.IndexOf(testBytes, (byte)0x0D) >= 0));
            
            // Use C# keys for encrypt/decrypt round-trip
            string keysJson = File.ReadAllText("D:/workspaces/git/corssmool/crossmool/testcase/keys/csharp/keys.json");
            var keys = JsonDocument.Parse(keysJson);
            string encPubKey = keys.RootElement.GetProperty("encryption_public_key").GetProperty("hex").GetString()!;
            string encPrivKey = keys.RootElement.GetProperty("encryption_private_key").GetProperty("hex").GetString()!;
            string signPrivKey = keys.RootElement.GetProperty("signature_private_key").GetProperty("hex").GetString()!;
            string signPubKey = keys.RootElement.GetProperty("signature_public_key").GetProperty("hex").GetString()!;
            
            // Encrypt + Sign
            var (ciphertextHex, signatureHex) = SM2Util.encryptSign(testStr, encPubKey, signPrivKey);
            
            // Verify + Decrypt
            string decrypted = SM2Util.verifyDecrypt(ciphertextHex, signatureHex, signPubKey, encPrivKey);
            
            byte[] decryptedBytes = Encoding.UTF8.GetBytes(decrypted);
            Console.WriteLine("\nDecrypted string hex: " + BitConverter.ToString(decryptedBytes).Replace("-", ""));
            Console.WriteLine("Decrypted has \\r (0D): " + (Array.IndexOf(decryptedBytes, (byte)0x0D) >= 0));
            Console.WriteLine("Match: " + (testStr == decrypted));
            
            // Output as base64 to avoid console interpretation
            Console.WriteLine("\nOriginal Base64: " + Convert.ToBase64String(testBytes));
            Console.WriteLine("Decrypted Base64: " + Convert.ToBase64String(decryptedBytes));
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }
}
