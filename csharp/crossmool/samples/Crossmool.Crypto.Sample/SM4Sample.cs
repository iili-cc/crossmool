using Crossmool.Crypto.Utils;

namespace Crossmool.Crypto.Sample;

/// <summary>
/// SM4 国密对称加密算法示例（GCM 模式）
///
/// 快速上手：
/// 1. 用 Visual Studio 或 Rider 打开 Crossmool.Crypto.sln
/// 2. 确认 samples/Crossmool.Crypto.Sample 已加载到解决方案中
/// 3. 运行本项目的 Program.cs
/// 4. 观察控制台输出，理解 SM4-GCM 加解密流程
///
/// 核心能力：
/// - 生成 SM4 密钥（128-bit，Hex / Base64 格式）
/// - SM4-GCM 加密（带认证标签，防篡改）
/// - SM4-GCM 解密（自动检测 Hex / Base64 输入）
/// - GCM 模式：任何篡改都会导致解密失败（防篡改验证）
/// </summary>
public static class SM4Sample
{
    /// <summary>
    /// 完整演示 SM4 的 密钥生成 / GCM加密 / GCM解密 / 防篡改验证
    /// </summary>
    public static void Run()
    {
        Console.WriteLine("============================================================");
        Console.WriteLine("  SM4 Sample — 国密对称加密 (GCM 模式)");
        Console.WriteLine("============================================================");
        Console.WriteLine();

        // ==================== 原始内容 ====================
        string originalContent = "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。";
        Console.WriteLine($"OriginalContent ::: {originalContent}");
        Console.WriteLine();

        // ==================== 1. 生成 SM4 密钥 ====================
        Console.WriteLine(">>> 1. 生成 SM4 密钥（128-bit）");

        string hexKey = SM4Util.GenerateKeyAsHex();
        Console.WriteLine($"  SM4 Hex Key    ::: {hexKey}");

        string base64Key = SM4Util.GenerateKeyAsBase64();
        Console.WriteLine($"  SM4 Base64 Key ::: {base64Key}");
        Console.WriteLine();

        // ==================== 2. Hex 密钥加解密 ====================
        Console.WriteLine(">>> 2. 使用 Hex 密钥进行 GCM 加解密");

        byte[] hexKeyBytes = SM4Util.ParseHexKey(hexKey);

        string encryptedHex = SM4Util.EncryptGcmString(hexKeyBytes, originalContent);
        Console.WriteLine($"  Encrypted (Hex) ::: {encryptedHex}");

        string decryptedHex = SM4Util.DecryptGcmToString(hexKeyBytes, encryptedHex);
        Console.WriteLine($"  Decrypted (Hex) ::: {decryptedHex}");

        bool equalsHex = originalContent == decryptedHex;
        Console.WriteLine($"  WhetherDecryptEqualsOriginalContent (Hex) ::: {equalsHex}");
        Console.WriteLine();

        // ==================== 3. Base64 密钥加解密 ====================
        Console.WriteLine(">>> 3. 使用 Base64 密钥进行 GCM 加解密");

        byte[] base64KeyBytes = EncodingUtils.FromBase64(base64Key);

        string encryptedBase64 = SM4Util.EncryptGcmString(base64KeyBytes, originalContent, toBase64: true);
        Console.WriteLine($"  Encrypted (Base64) ::: {encryptedBase64}");

        string decryptedBase64 = SM4Util.DecryptGcmToString(base64KeyBytes, encryptedBase64);
        Console.WriteLine($"  Decrypted (Base64) ::: {decryptedBase64}");

        bool equalsBase64 = originalContent == decryptedBase64;
        Console.WriteLine($"  WhetherDecryptEqualsOriginalContent (Base64) ::: {equalsBase64}");
        Console.WriteLine();

        // ==================== 4. GCM 防篡改验证 ====================
        Console.WriteLine(">>> 4. GCM 防篡改验证");
        Console.WriteLine("  （故意篡改密文末尾字符，GCM 应检测到并拒绝解密）");

        // 篡改 Hex 密文的最后 2 个字符
        string tampered = encryptedHex.Substring(0, encryptedHex.Length - 2) + "XX";
        try
        {
            string hacked = SM4Util.DecryptGcmToString(hexKeyBytes, tampered);
            Console.WriteLine($"  Tampered decrypted ::: {hacked}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  GCM detected tampering, decryption failed ::: {ex.Message}");
        }
        Console.WriteLine();

        Console.WriteLine("=== SM4 Sample 完成 ===");
        Console.WriteLine();
        /**
        ============================================================
        SM4 Sample — 国密对称加密 (GCM 模式)
        ============================================================

        OriginalContent ::: 今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。

        >>> 1. 生成 SM4 密钥（128-bit）
        SM4 Hex Key    ::: ac5d8beaf33acfad433b7d0670c3c9ed
        SM4 Base64 Key ::: 7SRKWzj/jUa65A5tgs+0hQ==

        >>> 2. 使用 Hex 密钥进行 GCM 加解密
        Encrypted (Hex) ::: 6a934a46c3ed1cb2c963907d79e86d77aa7c80d762894d536b4de8571c3fa2aad33b2dff600def7c9e8ec04203ad38a6233c6410d3e16c7224a1d5b3912975d83337f6bf19daa95498fc52d85a17230146402fd059859120c5a07b121c5d755c6ca150077420ea0c7cf6136d494c4c7fa6e1f6b2399f29db0a7d49b2ab3c9ba76f592d074b663a03f98d7576f028fc85e5d9fd672492ede5d3099a57dc9033def6fa0c844aa1fff2742498f508df7ca4f2cb98af2e0bbf7907fe0e83c181df1023982a2c15bbcd186c84805052d5f7050c4b96236eed60513593d61c102e9af023721553811eba5c16061de40d1006dffd2bd90e9663ea1d2f99802f6dc44fabc160981d22fea1365df596f5754d94fe52bace77612ca9e1a027ed273bcdd010d37c64f076c0fde13676a7fe598763462f76abbfdfb83a04037ba702d014d4a212080ceb2c3ece5c872ce3fed0ae7243f3608b7861859c3f724cfb7b8b9f3455a857706220f32d2f79d6efb6511a4719b9ce5d0c9dfdcc257c595cfa593fc3ead1ab6b2252463d0ca334cf0f1b2c24121a497c00ed50d8553460c53a9ac6b16a72d6bafab5633034404f20b74f9e62bd877251906d3126ed1e162b9491b2777c80dec8608e990243f99c1b
        Decrypted (Hex) ::: 今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
        WhetherDecryptEqualsOriginalContent (Hex) ::: True

        >>> 3. 使用 Base64 密钥进行 GCM 加解密
        Encrypted (Base64) ::: NfKbmMuSlKfZzYAlL65A7UCoPfzMzkBnmD3Gq3yTz+J5a0eN6RYyLNdj2edbKimNzN/NBP7a10iHaCAhl8l0uefLDHJt0SZMZ7V+KKxt9RujNKrlmWAXDnJBfUJSoY7/XeqRdmUJZlogibet4z5ryjTpWv57FQCkRj+iFQCOVsJz78BfmWGkWyAV0jrN9FKE73OsGdhMBtJoA1rl4vrN5YGFeiF65epWq+dE3NuYKyB7RQKcFldPZqXSVZg2MKbITh8iGrlQ+k0+WbSAclShZaRZUMcL+YJ/AXTcNlnRsuuRDFPnQYZo4KNXMo1OqHOLaR6ohut76jajVRArbi4Hw9slQpTlNlQYmENn1xPvDOfxEakx98U/7etr9E5xmrYCfax0Fql5gHGBYlClcdayW/YCTDLTCQ7lSHK1j7VF1Cs/sAwg6HK7ErI23C2yjLzxZDrAlzhgyzuTPHnn7l1eJSwu/Dq+9zBng9GZGPOvn2VNdfcceWM8fUj1yEPvnwzaG+ITm5lpVuMjDUz4ySfvdL/Hoy4xnyft1cL4nFdtsNUsyrkbM3UXUfoxwuW/OoC8g7xHDm7tD0gI/9RPy063qse25STW/pX83/EV
        Decrypted (Base64) ::: 今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
        WhetherDecryptEqualsOriginalContent (Base64) ::: True

        >>> 4. GCM 防篡改验证
        （故意篡改密文末尾字符，GCM 应检测到并拒绝解密）
        GCM detected tampering, decryption failed ::: Could not find any recognizable digits.

        === SM4 Sample 完成 ===
        */
    }
}
