namespace Crossmool.Crypto.Sample;

/// <summary>
/// SM3 国密哈希算法示例
///
/// 快速上手：
/// 1. 用 Visual Studio 或 Rider 打开 Crossmool.Crypto.sln
/// 2. 确认 samples/Crossmool.Crypto.Sample 已加载到解决方案中
/// 3. 运行本项目的 Program.cs
/// 4. 观察控制台输出，理解 SM3 摘要和 HMAC 的用法
///
/// 核心能力：
/// - SM3 消息摘要（256-bit，类似 SHA-256）
/// - HMAC-SM3 消息认证码（防篡改 + 防伪造）
/// - 支持 Hex / Base64 输出
/// </summary>
public static class SM3Sample
{
    /// <summary>
    /// 完整演示 SM3 的 消息摘要 / HMAC 密钥生成 / HMAC 计算
    /// </summary>
    public static void Run()
    {
        Console.WriteLine("============================================================");
        Console.WriteLine("  SM3 Sample — 国密哈希算法 (256-bit)");
        Console.WriteLine("============================================================");
        Console.WriteLine();

        // ==================== 1. SM3 消息摘要 ====================
        Console.WriteLine(">>> 1. SM3 消息摘要 (Digest)");

        string input = "在这个全球化时代，無論身處何地，learning and growth are always the keys to a fulfilling life.";
        Console.WriteLine($"  Input        ::: {input}");

        string hash = SM3Util.digest(input);
        Console.WriteLine($"  SM3 Hash     ::: {hash}");

        // 显式指定 Hex 输出（与默认行为一致）
        string hashHex = SM3Util.digest(input, toBase64: false);
        Console.WriteLine($"  SM3 Hash (Hex) ::: {hashHex}");

        bool equals = hash == hashHex;
        Console.WriteLine($"  Whether Hash Equals Hex ::: {equals}");
        Console.WriteLine();

        // ==================== 2. HMAC-SM3 消息认证码 ====================
        Console.WriteLine(">>> 2. HMAC-SM3 消息认证码");

        // 生成 HMAC 密钥（32 字节 = 256-bit）
        string hmacKey = SM3Util.generateHmacKeyToStr();
        Console.WriteLine($"  HMAC Key      ::: {hmacKey}");

        // 计算 HMAC（Hex 输出）
        string hmacValue = SM3Util.hmacToStr(input, hmacKey);
        Console.WriteLine($"  HMAC Value    ::: {hmacValue}");

        // 相同密钥 + 相同输入 → 相同输出（确定性）
        string hmacValue2 = SM3Util.hmacToStr(input, hmacKey);
        Console.WriteLine($"  HMAC Value 2  ::: {hmacValue2}");

        bool hmacEquals = hmacValue == hmacValue2;
        Console.WriteLine($"  Whether HMAC Values Equal ::: {hmacEquals}");
        Console.WriteLine();

        // ==================== 3. HMAC 校验 ====================
        Console.WriteLine(">>> 3. HMAC 校验（防篡改验证）");

        bool hmacVerified = SM3Util.hmacVerify(input, hmacKey, hmacValue);
        Console.WriteLine($"  HMAC Verify (correct)   ::: {hmacVerified}");

        // 篡改消息后校验失败
        bool hmacTampered = SM3Util.hmacVerify(input + "X", hmacKey, hmacValue);
        Console.WriteLine($"  HMAC Verify (tampered)  ::: {hmacTampered}");
        Console.WriteLine();

        // ==================== 4. Base64 输出示例 ====================
        Console.WriteLine(">>> 4. Base64 格式输出（可选）");

        string hashB64 = SM3Util.digest(input, toBase64: true);
        Console.WriteLine($"  SM3 Hash (Base64) ::: {hashB64}");

        string hmacKeyB64 = SM3Util.generateHmacKeyToStr(toBase64: true);
        Console.WriteLine($"  HMAC Key (Base64) ::: {hmacKeyB64}");
        Console.WriteLine();

        Console.WriteLine("=== SM3 Sample 完成 ===");
        Console.WriteLine();
        /**
        ============================================================
        SM3 Sample — 国密哈希算法 (256-bit)
        ============================================================

        >>> 1. SM3 消息摘要 (Digest)
        Input        ::: 在这个全球化时代，無論身處何地，learning and growth are always the keys to a fulfilling life.
        SM3 Hash     ::: 54e020abea7ebe39b25e768541f00f750b7784f0ce29b7dd71fdd2b8761f9773
        SM3 Hash (Hex) ::: 54e020abea7ebe39b25e768541f00f750b7784f0ce29b7dd71fdd2b8761f9773
        Whether Hash Equals Hex ::: True

        >>> 2. HMAC-SM3 消息认证码
        HMAC Key      ::: 5b622fe6869d3811a38ad46e88a28a0f0d53b8ec9d587a97db268641327cfeb5
        HMAC Value    ::: a9e3677d6627ffeccc6872d7366a837c662237e6f17d57609d1aaef420417ae2
        HMAC Value 2  ::: a9e3677d6627ffeccc6872d7366a837c662237e6f17d57609d1aaef420417ae2
        Whether HMAC Values Equal ::: True

        >>> 3. HMAC 校验（防篡改验证）
        HMAC Verify (correct)   ::: True
        HMAC Verify (tampered)  ::: False

        >>> 4. Base64 格式输出（可选）
        SM3 Hash (Base64) ::: VOAgq+p+vjmyXnaFQfAPdQt3hPDOKbfdcf3SuHYfl3M=
        HMAC Key (Base64) ::: ZAb2JDHLRuJGQaHsWB6NqQcmpPAtnPzpPR+FiAzVX9E=

        === SM3 Sample 完成 ===
        */

    }
}
