import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM2KeyUtil;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * 诊断：Java SM2 签名与 C GmSSL 签名不兼容问题
 * 输出签名的详细字节信息，方便与 C 对比
 */
public class SM2SignDiagnostics {
    
    // 与 C 一致的 USER_ID
    private static final String USER_ID = "1234567812345678";
    
    public static void main(String[] args) throws Exception {
        System.out.println("=== SM2 签名诊断工具 ===\n");
        
        // 使用 testcase/keys/java/keys.json 中的密钥
        String privateKeyHex = "308193020100301306072a8648ce3d020106082a811ccf5501822d0479307702010104206c7e16537962cdbd57cc9cf430235a9d89e80a14803bfa2e1926eab5d242a69ba00a06082a811ccf5501822da14403420004a4e1c5b480d6e4e321d2db4f792128c1d7044399c89ad139fd5cb9e3f8cab9dd57e68f27f645f29e50cc592b395c7f863db40f9979e1cba0bac61b3b866633";
        String publicKeyHex = "3059301306072a8648ce3d020106082a811ccf5501822d03420004a4e1c5b480d6e4e321d2db4f792128c1d7044399c89ad139fd5cb9e3f8cab9dd57e68f27f645f29e50cc592b395c7f863db40f9979e1cba0bac61b3b866633";
        
        String testContent = "Hello SM2 Cross Verification!";
        
        System.out.println("测试内容: " + testContent);
        System.out.println("内容字节 (UTF-8): " + bytesToHex(testContent.getBytes(StandardCharsets.UTF_8)));
        System.out.println();
        
        // 1. Java 签名
        System.out.println("=== Java BouncyCastle 签名 ===");
        String sigHex = SM2Util.signToHex(testContent, privateKeyHex);
        byte[] sigDer = hexToBytes(sigHex);
        
        System.out.println("签名 Hex (DER): " + sigHex);
        System.out.println("签名长度 (DER): " + sigDer.length + " 字节");
        
        // 解析 DER 格式的 r, s
        DLSequence seq = (DLSequence) DLSequence.getInstance(sigDer);
        ASN1Integer rAsn = (ASN1Integer) seq.getObjectAt(0);
        ASN1Integer sAsn = (ASN1Integer) seq.getObjectAt(1);
        
        byte[] rBytes = rAsn.getValue().toByteArray();
        byte[] sBytes = sAsn.getValue().toByteArray();
        
        // 去除 DER 编码可能添加的前导零
        rBytes = removeLeadingZero(rBytes);
        sBytes = removeLeadingZero(sBytes);
        
        System.out.println("\nr 值 (Hex, 去前导零): " + bytesToHex(rBytes));
        System.out.println("r 值长度: " + rBytes.length + " 字节");
        System.out.println("r 值 (BigInteger): " + rAsn.getValue().toString());
        
        System.out.println("\ns 值 (Hex, 去前导零): " + bytesToHex(sBytes));
        System.out.println("s 值长度: " + sBytes.length + " 字节");
        System.out.println("s 值 (BigInteger): " + sAsn.getValue().toString());
        
        // 输出 raw 格式 (r || s)
        byte[] rawSig = new byte[64];
        System.arraycopy(rBytes, 0, rawSig, 32 - rBytes.length, rBytes.length);
        System.arraycopy(sBytes, 0, rawSig, 64 - sBytes.length, sBytes.length);
        System.out.println("\nRaw 签名 (r||s 64字节): " + bytesToHex(rawSig));
        
        // 2. 验证 Java 签名（自验）
        System.out.println("\n=== Java 自验签 ===");
        boolean selfVerify = SM2Util.verify(testContent, publicKeyHex, sigHex);
        System.out.println("自验结果: " + (selfVerify ? "PASS" : "FAIL"));
        
        // 3. 输出公钥信息
        System.out.println("\n=== 公钥信息 ===");
        byte[] pubKeyBytes = hexToBytes(publicKeyHex);
        System.out.println("公钥 X.509 Hex: " + publicKeyHex);
        System.out.println("公钥长度: " + pubKeyBytes.length + " 字节");
        
        // 提取公钥的 X, Y 坐标
        // X.509 格式: 30 59 30 13 ... 03 42 00 04 [X 32字节] [Y 32字节]
        if (pubKeyBytes.length >= 91) {
            byte[] xBytes = new byte[32];
            byte[] yBytes = new byte[32];
            System.arraycopy(pubKeyBytes, 91 - 64, xBytes, 0, 32);
            System.arraycopy(pubKeyBytes, 91 - 32, yBytes, 0, 32);
            System.out.println("公钥 X: " + bytesToHex(xBytes));
            System.out.println("公钥 Y: " + bytesToHex(yBytes));
        }
        
        // 4. 输出 USER_ID 信息
        System.out.println("\n=== USER_ID 信息 ===");
        System.out.println("USER_ID: " + USER_ID);
        System.out.println("USER_ID 字节 (Hex): " + bytesToHex(USER_ID.getBytes(StandardCharsets.UTF_8)));
        System.out.println("USER_ID 长度: " + USER_ID.getBytes(StandardCharsets.UTF_8).length + " 字节");
        
        // 5. 保存诊断信息到文件（供 C 程序读取）
        System.out.println("\n=== 供 C 程序使用的数据 ===");
        System.out.println("内容 Hex: " + bytesToHex(testContent.getBytes(StandardCharsets.UTF_8)));
        System.out.println("Java 签名 DER Hex: " + sigHex);
        System.out.println("Java 签名 Raw Hex: " + bytesToHex(rawSig));
        
        // 保存到文件
        String output = "CONTENT_HEX=" + bytesToHex(testContent.getBytes(StandardCharsets.UTF_8)) + "\n";
        output += "CONTENT=" + testContent + "\n";
        output += "SIG_DER_HEX=" + sigHex + "\n";
        output += "SIG_RAW_HEX=" + bytesToHex(rawSig) + "\n";
        output += "R_HEX=" + bytesToHex(rBytes) + "\n";
        output += "S_HEX=" + bytesToHex(sBytes) + "\n";
        output += "PUBLIC_KEY_HEX=" + publicKeyHex + "\n";
        output += "PRIVATE_KEY_HEX=" + privateKeyHex + "\n";
        output += "USER_ID=" + USER_ID + "\n";
        output += "USER_ID_HEX=" + bytesToHex(USER_ID.getBytes(StandardCharsets.UTF_8)) + "\n";
        
        java.nio.file.Files.write(
            java.nio.file.Paths.get("sm2_diag_data.txt"),
            output.getBytes(StandardCharsets.UTF_8)
        );
        System.out.println("\n诊断数据已保存到 sm2_diag_data.txt");
    }
    
    private static byte[] removeLeadingZero(byte[] bytes) {
        // DER INTEGER 可能在正数值前添加 0x00 字节
        if (bytes.length > 32 && bytes[0] == 0x00) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
