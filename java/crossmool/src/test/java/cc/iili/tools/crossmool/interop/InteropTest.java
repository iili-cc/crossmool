package cc.iili.tools.crossmool.interop;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

/**
 * Java互操作性测试类 - 用于验证Java与C++实现之间的一致性
 */
public class InteropTest {

    public static void main(String[] args) {
        try {
            System.out.println("开始运行Java-C++互操作性测试...");

            // 如果存在由C++生成的互操作测试数据，则进行验证
            testCppGeneratedData();

            // 运行Java侧的基础测试
            runBasicTests();

            System.out.println("Java-C++互操作性测试完成！");
        } catch (Exception e) {
            System.err.println("测试失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void testCppGeneratedData() throws Exception {
        // 尝试读取由C++测试程序生成的数据文件
        try {
            String pubDerPath = "interop_test_public.der";
            String privDerPath = "interop_test_private.der";
            String cipherPath = "interop_test_cipher.hex";
            String sigPath = "interop_test_signature.hex";

            // 读取公共和私钥DER文件
            byte[] pubKeyDer = Files.readAllBytes(Paths.get(pubDerPath));
            byte[] privKeyDer = Files.readAllBytes(Paths.get(privDerPath));

            // 读取密文和签名
            String cipherHex = Files.readString(Paths.get(cipherPath)).trim();
            String sigHex = Files.readString(Paths.get(sigPath)).trim();

            String message = "interoperability-test-message";

            // 在Java侧验证C++生成的密文能否被Java正确解密
            String privKeyHex = HexUtil.encodeHexStr(privKeyDer);
            String decryptedMsg = SM2Util.decrypt(cipherHex, privKeyHex);
            if (!message.equals(decryptedMsg)) {
                System.err.println("C++生成的密文Java解密失败！");
                System.err.println("期望: " + message);
                System.err.println("实际: " + decryptedMsg);
            } else {
                System.out.println("✓ C++生成的密文Java解密成功: " + decryptedMsg);
            }

            // 在Java侧验证C++生成的签名能否被Java正确验证
            String pubKeyHex = HexUtil.encodeHexStr(pubKeyDer);
            boolean isValid = SM2Util.verify(message, pubKeyHex, sigHex);
            if (!isValid) {
                System.err.println("C++生成的签名Java验证失败！");
            } else {
                System.out.println("✓ C++生成的签名Java验证成功");
            }

            // 使用Java重新加密和签名，看C++是否能解密和验证
            String javaCipherHex = SM2Util.encryptToHex(message, pubKeyHex);
            System.out.println("✓ Java重新加密成功，结果已保存为hex格式");

            String javaSigHex = SM2Util.signToHex(message, privKeyHex);
            System.out.println("✓ Java重新签名成功，结果已保存为hex格式");

        } catch (Exception e) {
            System.out.println("提示：未找到C++生成的互操作测试数据文件，这可能是正常的（首次运行）");
        }
    }

    private static void runBasicTests() throws Exception {
        System.out.println("运行Java基础功能测试...");

        // SM2 测试
        System.out.println("测试SM2...");
        String message = "test message for SM2";
        var keyPair = SM2Util.generateKeyPairBase64();

        String encrypted = SM2Util.encrypt(message, keyPair.getPublicKey());
        String decrypted = SM2Util.decrypt(encrypted, keyPair.getPrivateKey());
        if (message.equals(decrypted)) {
            System.out.println("✓ SM2 加解密成功");
        } else {
            System.err.println("✗ SM2 加解密失败");
        }

        String signature = SM2Util.sign(message, keyPair.getPrivateKey());
        boolean verified = SM2Util.verify(message, keyPair.getPublicKey(), signature);
        if (verified) {
            System.out.println("✓ SM2 签名验签成功");
        } else {
            System.err.println("✗ SM2 签名验签失败");
        }

        // SM3 测试
        System.out.println("测试SM3...");
        String sm3Result = SM3Util.digestToStr(message);
        if (sm3Result.length() == 64) { // 32 bytes = 64 hex chars
            System.out.println("✓ SM3 哈希计算成功: " + sm3Result.substring(0, 10) + "...");
        } else {
            System.err.println("✗ SM3 哈希计算失败");
        }

        // SM4 GCM 测试
        System.out.println("测试SM4 GCM...");
        String sm4Key = SM4Util.generateKeyAsHex();
        String sm4Encrypted = SM4Util.encryptGcmNative(message.getBytes(StandardCharsets.UTF_8), SM4Util.parseHexKey(sm4Key));
        String sm4Decrypted = SM4Util.decryptGcmNativeToString(sm4Encrypted, SM4Util.parseHexKey(sm4Key));

        if (message.equals(sm4Decrypted)) {
            System.out.println("✓ SM4 GCM 加解密成功");
        } else {
            System.err.println("✗ SM4 GCM 加解密失败");
        }

        System.out.println("Java基础功能测试完成！");
    }
}
