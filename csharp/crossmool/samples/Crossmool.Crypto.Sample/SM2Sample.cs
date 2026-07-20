namespace Crossmool.Crypto.Sample;

/// <summary>
/// SM2 国密非对称加密算法示例
///
/// 快速上手：
/// 1. 用 Visual Studio 或 Rider 打开 Crossmool.Crypto.sln
/// 2. 确认 samples/Crossmool.Crypto.Sample 已加载到解决方案中
/// 3. 运行本项目的 Program.cs，它会依次调用 SM2Sample、SM3Sample、SM4Sample
/// 4. 观察控制台输出，验证加解密、签名验签是否正确
///
/// 核心能力：
/// - 生成 SM2 密钥对（Hex / Base64）
/// - 公钥加密 → 私钥解密
/// - 私钥签名 → 公钥验签
/// - 先加密再签名 → 先验签再解密（防篡改 + 防抵赖）
/// - PEM 格式导入导出
/// </summary>
public static class SM2Sample
{
    /// <summary>
    /// 完整演示 SM2 的 密钥生成 / 加解密 / 签名验签 / 加密签名组合
    /// </summary>
    public static void Run()
    {
        Console.WriteLine("============================================================");
        Console.WriteLine("  SM2 Sample — 国密非对称加密 (SM2P256V1)");
        Console.WriteLine("============================================================");
        Console.WriteLine();

        // ==================== 原始内容 ====================
        string originalContent = "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。";
        Console.WriteLine($"OriginalContent ::: {originalContent}");
        Console.WriteLine();

        // ==================== 生成两对密钥 (第1对用于加解密, 第2对用于签名) ====================
        Console.WriteLine(">>> 1. 生成两对 SM2 密钥");
        var (pubKey1, priKey1) = SM2Util.generateKeyPairHex();
        var (pubKey2, priKey2) = SM2Util.generateKeyPairHex();

        Console.WriteLine($"  privateKeyHex-1 ::: {priKey1}");
        Console.WriteLine($"  publicKeyHex-1  ::: {pubKey1}");
        Console.WriteLine($"  privateKeyHex-2 ::: {priKey2}");
        Console.WriteLine($"  publicKeyHex-2  ::: {pubKey2}");
        Console.WriteLine();

        // ==================== 2. 加密并签名 / 验签并解密 ====================
        Console.WriteLine(">>> 2. 加密并签名 → 验签并解密（先加密再签名，先验签再解密）");

        var (ciphertext, signature) = SM2Util.encryptSign(originalContent, pubKey1, priKey2);
        Console.WriteLine($"  CipherText ::: {ciphertext}");
        Console.WriteLine($"  Signature  ::: {signature}");
        Console.WriteLine();

        string verifyDecrypt = SM2Util.verifyDecrypt(ciphertext, signature, pubKey2, priKey1);
        Console.WriteLine($"  VerifyDecrypt ::: {verifyDecrypt}");
        Console.WriteLine($"  WhetherVerifyDecryptEqualsOriginalContent ::: {originalContent == verifyDecrypt}");
        Console.WriteLine();

        // ==================== 3. 仅加密/解密 ====================
        Console.WriteLine(">>> 3. 公钥加密 → 私钥解密");

        string encryptedContent = SM2Util.encryptToHex(originalContent, pubKey1);
        Console.WriteLine($"  EncryptedContent ::: {encryptedContent}");

        string decryptedContent = SM2Util.decrypt(encryptedContent, priKey1);
        Console.WriteLine($"  DecryptedContent ::: {decryptedContent}");
        Console.WriteLine($"  WhetherDecryptEqualsOriginalContent ::: {originalContent == decryptedContent}");
        Console.WriteLine();

        // ==================== 4. 签名/验签 ====================
        Console.WriteLine(">>> 4. 私钥签名 → 公钥验签");

        string contentSignature = SM2Util.signToHex(originalContent, priKey2);
        Console.WriteLine($"  ContentSignature ::: {contentSignature}");

        bool verify = SM2Util.verify(originalContent, contentSignature, pubKey2);
        Console.WriteLine($"  WhetherVerifyEqualsOriginalContent ::: {verify}");
        Console.WriteLine();

        // ==================== 5. Base64 输出示例 ====================
        Console.WriteLine(">>> 5. Base64 格式输出（可选）");

        string encryptedB64 = SM2Util.encryptToBase64(originalContent, pubKey1);
        Console.WriteLine($"  Encrypted (Base64) ::: {encryptedB64}");

        string signatureB64 = SM2Util.signToBase64(originalContent, priKey2);
        Console.WriteLine($"  Signature  (Base64) ::: {signatureB64}");
        Console.WriteLine();

        Console.WriteLine("=== SM2 Sample 完成 ===");
        Console.WriteLine();

        /**
        ============================================================
        SM2 Sample — 国密非对称加密 (SM2P256V1)
        ============================================================

        OriginalContent ::: 今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。

        >>> 1. 生成两对 SM2 密钥
        privateKeyHex-1 ::: 732eb232e7a25446077eb652c771edcf05f42fa42d89fb77f25fbd217272dd23
        publicKeyHex-1  ::: 04eb70b392403b1f27bb6b9c16d04b79b5a03b596abaadbd97b562b228b5da49a5884f74a42414cab939203eb569778f5af046a83e6eef01e5180bbb7472d5ffb5
        privateKeyHex-2 ::: fafc7409de2d1cb577e4881ff636fe9f1cbea9060a1326d39d777f786a82d0f4
        publicKeyHex-2  ::: 049cc161f255c070d129d517c9ba50cf7e78434e609ab2f1490b95eb8691d42b1175f72ab47c5d0802342895f4885a893c84ef03a42cf1c9a1d5d9425812f2b9fb

        >>> 2. 加密并签名 → 验签并解密（先加密再签名，先验签再解密）
        CipherText ::: 04ceab0c3991c391bcacd97dc55a624f1cf542c6eba2d9442a4f29693234d460d9d4cdb4478184e289077f5d2d5eaaca9563e415b3c709f1af8e60c3a719951fe849028a9a39ff0f81a2191e3adf5d887f3bc5694d7b5a326484233c5726bf9c79ff38a862064902eacabe6cd3f7dc5c69e34a55d4ee8eea2c32811540227a04087670eb11c227a5bb1ca63b1fb4690b8a088a05295cbc11740cd00fb13f3026fee73ebe7fd141801b7d24e4717a72b535a58a82fd3a1e783874e8b98535d443140187ab29c1ee0555fb136e687b50813aa587dac3fcb31c80b28eebd4ada052888d5beb2f6ddbaeb9eaf135f5158c31f2a9d06501f00af443c281594abfe6d41c5c84bc3cacef5bdf69e18db8f6b28ca78fa79f70cbecf990c677550b8ea22d78cdfb32941ceff7adc2fee5a492857f6009481254efe254cf23fce2563cbda9390145e2fee8c5cf59fa72846ec410e7bfbc65b92940c34d469465813510a0a9a5604295e9e305aef2b950f68ad571bd662a2ffbd47bdc5eadf3f0de1ddeafa9da77111590f4e256d6c3380ef898d4d21a24cd0a9b3de8c43b2d224a00c8bc68105dffba1164541b7cbce693b1cd336b31eda3f996a6ffa6e15e3db02e7233a02ecc1a7e71019eb0917455e822c7843bc5af29461945f70c81189224bf6fb87b3c31cbc3929cd93d611444ae647015aa014832360b4ad2cd17b7ce610a0382a6b2db0eebad30c8f70e97c650b4ab8b69
        Signature  ::: 3046022100d2cee21f2e95f3b80011701f52e1b0491f948c90376dc2ea84076c636724997b022100b00ae49fbaaf6f09d6390222f08f16653c3eef200638d249c63b726e10f3001e

        VerifyDecrypt ::: 今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
        WhetherVerifyDecryptEqualsOriginalContent ::: True

        >>> 3. 公钥加密 → 私钥解密
        EncryptedContent ::: 048f6889f1e30cd10907bd150a2fa2968f1117b020afc905f36cbaa54f3d450962cf28b224cedb83b740f72977894eaf2cc7a5737ef8a556247daeb680bfae125f41fe481085798372cd38e4e15830abe927b144cc9dc64b2535bf450e37d058119b9d647880c4036900b2c4e7538f1c16b140221209bede5f504b1cdddeaa7a81197112197b769ab87dc0f8305b76637cf2338f4e3371576d257d1300bc0ba3e76cbe3ac655fc7f0418dfb456efc8a2c8f5f389b4462d11dd3d68a4f86f85c85c17bb5d7c90b42b0b641f743c3bad572dda7e2f1977da139121e009c61fce4c89eae065d4a613db95762f4e6c1f3ed0dad65729fa22b40adb7e0d8052c9d9f48cce2e8344c9e2db0fa7fc0497bd79c6aec9f54c238bc40b7b7fd258d41e09b5a71f16bd687006233207b4f1ce02669cc0fa03287cd2ecbb8f85e43a5f9debc2a1c35d1f84df6b26392071c68dd46b8f2ce615b7ed3dee53d0fffd9f8eab6aa8f90825cdb4935002b2126b4c43e436b5df154ac405cd5a90d2a5266b02ffdd0b9f29f2d9a1eed224d0b1dcaa5c544c6a4a62f27d9bd9afeded679c2ebfde80a9b787d38ee4f47194290f81f511eb650c09601a91a49c1687e1b357227ab8ddaa7171ddc6698d9f3ef1a5154835fa29e8b89d0ed1b628facb4dc41e93fcc9a56d594d5339f8f69ddffcf679cb8bb1555ca2a141e7e2180f9a57ac6204c1fdcc52a5d6304510ecdf154fa6d650e93964d7
        DecryptedContent ::: 今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don't forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。
        WhetherDecryptEqualsOriginalContent ::: True

        >>> 4. 私钥签名 → 公钥验签
        ContentSignature ::: 3045022045540344037026dd15e75ba7fef628aab7c5a1cc32df352735e5ab851dc0609802210092cef21e962e2d0a75fb0a6fa71ffdaaf86dd568bcb06787eed0ab1767a6720b
        WhetherVerifyEqualsOriginalContent ::: True

        >>> 5. Base64 格式输出（可选）
        Encrypted (Base64) ::: BI6pQbYg7270Q6IpAQCM9S0Peaa5v2cERZjJLj1aHZzUKSzzNBy0UXSmMjAH6JyXseXsu3LTMfG5e6vEU2E55gWD7ZWqnqfAv/BR4vwPNmsC71tbJv7igAUfHdE+F4EAjZZbas4ep327KspDotiIGCiLZdvxug15zdXORj78UoY6eQ6cYDjUiK5bYCSiVWVTsWXmTsm3zGvtatOxwm0DZSwUSNiG+wegavo/tw9qDmOTpZ75xCGH4IYCS20mr4ximOcMv8Y8QQdb/vVBtZA5EZWf47gPabwrVNx17mJ/okwfCb7vvomQxHS9AM+Ujau/6qoLlMT9iG+T2BElL3ARXC+g9QsGuZ/LXCZaOEAIO81PtsqP7f62nknXoxrLoXbBeayY1xlA3C5/x/FeRDcjPt7M3JXb+KU60xxX1oUYALIbAdTBk+YYUKTE7xg7tYgIo5Gd2h0nvBR02e/54PiN3TrHgpiAJp1hfL5enkRU6XrCW2cCoi67q8oe13wfHUj92HwehhdGkuZ3LsWmA3MCOJohczTR/ldDGmuzXr9jKh+1sL2Qj/OT21Quu+CulPQJeqabOb6YUZ00028grSa88g4014lsNT4I7RoY+LtA4mPaDsp9KtoJ2NZnElQIPYghzePK4yVubbFLvkUSIw8groKL6aSoswAoyhIwFu20EF2U8t+PvZy70jgZyT2eMp2p
        Signature  (Base64) ::: MEQCHyECkbd3lmGfhO4Kb9LEHFmyYJmXsdMhKjVkiT/N8ugCIQC4LDSZ9dZlf6R1rtEnwPtN1IUQ5v2nvg1BHsf0O+oQTw==

        === SM2 Sample 完成 ===
        */
    }

}
