using System;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;

class CrossLangTest
{
    static void Main(string[] args)
    {
        var keyHex = "ad1486d58d4e012d4c94936616ecf7d6";
        var key = EncodingUtils.FromHex(keyHex);
        var expectedMessage = "Hello, 這是国密SM4測試數據";
        
        Console.WriteLine("=== SM4 GCM Cross-Language Interop Test ===");
        
        // Test 1: C# self-test
        var csCt = SM4Util.EncryptGcmString(key, expectedMessage);
        var csPt = SM4Util.DecryptGcmToString(key, csCt);
        Console.WriteLine($"[C# self-test] Match: {csPt == expectedMessage}");
        
        // Test 2: Decrypt Java Native GCM ciphertext
        var javaNativeCt = "9ud33pnp80PrjMCaf7i25R/mZVve+eEjrddhu4fv19axPD/jhLAEaVQfT9i8/2jJxIWR00cjk8LYmVbityo=";
        try {
            var javaPt = SM4Util.DecryptGcmToString(key, javaNativeCt);
            Console.WriteLine($"[Java(Native)->C#] Match: {javaPt == expectedMessage} (got: {javaPt})");
        } catch (Exception e) {
            Console.WriteLine($"[Java(Native)->C#] FAIL: {e.Message}");
        }
        
        // Test 3: Decrypt Java JCA GCM ciphertext
        var javaJcaCt = "zwDiv77YRtE1H/f0aBGKCKyUrC/A5oYqnB3ZHHCektCW28HsO3pszlRvtKQF1LHugKILvIdlLy8ooMrr/Zc=";
        try {
            var javaJcaPt = SM4Util.DecryptGcmToString(key, javaJcaCt);
            Console.WriteLine($"[Java(JCA)->C#] Match: {javaJcaPt == expectedMessage} (got: {javaJcaPt})");
        } catch (Exception e) {
            Console.WriteLine($"[Java(JCA)->C#] FAIL: {e.Message}");
        }
        
        // Test 4: Decrypt Python GCM ciphertext (if provided as arg)
        if (args.Length > 0) {
            var pythonCt = args[0];
            try {
                var pythonPt = SM4Util.DecryptGcmToString(key, pythonCt);
                Console.WriteLine($"[Python->C#] Match: {pythonPt == expectedMessage} (got: {pythonPt})");
            } catch (Exception e) {
                Console.WriteLine($"[Python->C#] FAIL: {e.Message}");
            }
        }
        
        // Test 5: C# encrypt -> output for other languages to verify
        var csCt2 = SM4Util.EncryptGcmString(key, expectedMessage);
        Console.WriteLine($"[C# encrypted for verification]: {csCt2}");
    }
}
