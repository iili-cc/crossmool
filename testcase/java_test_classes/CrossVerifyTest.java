package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;

/**
 * 交叉验证测试：
 * 1. 用 Java SM2Util 对同一内容签名
 * 2. 验证 Python (gmssl-python) 的签名能否被 Java 验签通过
 * 3. 验证 Java 的签名能否被 Java 自身验签通过
 *
 * 运行方式: java testcase.CrossVerifyTest
 */
public class CrossVerifyTest {
    public static void main(String[] args) {
        String publicKey = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        String privateKey = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";

        // 测试内容：密文 hex 字符串（与 Java encryptSign 的签名内容一致）
        String message = "046a2146cffa0e592b74f49304a75eb73449be5ae5f7cabac4a3938ae34539207472a2b912701a096ad7182772cede4439cc0642c3b56d123ca9c8b11b569ab94197d41b436a9240ef89ed76d01bee13129c5abc6aefa0d262424f147382f478fae20b93b2b671f0a33eec6a00830f44a191";

        // 测试 1: Java 自签自验
        System.out.println("=== Test 1: Java self-sign and self-verify ===");
        try {
            String javaSig = SM2Util.sign(message, privateKey, false);
            System.out.println("Java signature: " + javaSig);
            boolean verified = SM2Util.verify(message, publicKey, javaSig);
            System.out.println("Java self-verify: " + (verified ? "PASS" : "FAIL"));
        } catch (Exception e) {
            System.out.println("Java self-sign/verify ERROR: " + e.getMessage());
            e.printStackTrace();
        }

        // 测试 2: 验证 Python (gmssl-python) 的签名
        // Python 的签名是 r||s 格式（64 字节 = 128 hex chars）
        // BouncyCastle SM2Signer.verifySignature 期望 DER 格式签名（30 开头）
        // 需要把 r||s 转为 DER
        System.out.println("\n=== Test 2: Verify Python signature with Java ===");
        String pySigR = "992459327212d5cab77cbc7c864e540be3610704ebb432d1aae3830f8073517d";
        String pySigS = "9073105b4bcba96da183f7f875fa23c784318b2de4e916d3f4841a23393f64de";

        // 将 r||s 转为 DER SEQUENCE 格式
        byte[] rBytes = hexToBytes(pySigR);
        byte[] sBytes = hexToBytes(pySigS);
        try {
            // 构建 DER: SEQUENCE { INTEGER r, INTEGER s }
            byte[] derSig = buildDerSignature(rBytes, sBytes);
            String derSigHex = bytesToHex(derSig);
            System.out.println("Python sig DER: " + derSigHex);

            // 用 Java 验签
            // SM2Util.verify 的签名参数期望 Hex 字符串（可以是 DER 或 r||s 格式）
            boolean pyVerified = SM2Util.verify(message, publicKey, derSigHex);
            System.out.println("Python sig Java verify: " + (pyVerified ? "PASS" : "FAIL"));
        } catch (Exception e) {
            System.out.println("Python sig verify ERROR: " + e.getMessage());
            e.printStackTrace();
        }

        // 测试 3: 用 Java 签一个简单消息，输出签名和 e 值，方便 Python 验签
        System.out.println("\n=== Test 3: Java sign simple message for Python verify ===");
        String simpleMsg = "Hello, Crossmool!";
        try {
            String javaSig2 = SM2Util.sign(simpleMsg, privateKey, false);
            System.out.println("Message: " + simpleMsg);
            System.out.println("Java signature (DER hex): " + javaSig2);
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
        }

        // 测试 4: 直接用 byte[] API
        System.out.println("\n=== Test 4: Byte-level API test ===");
        try {
            byte[] msgBytes = message.getBytes("UTF-8");
            byte[] sigBytes = SM2Util.sign(msgBytes, hexToBytes(privateKey));
            System.out.println("Java sig (raw bytes hex): " + bytesToHex(sigBytes));
            System.out.println("Java sig first byte: " + String.format("%02x", sigBytes[0]));

            boolean ok = SM2Util.verify(msgBytes, sigBytes, hexToBytes(publicKey));
            System.out.println("Byte-level verify: " + (ok ? "PASS" : "FAIL"));

            // 验证 Java 原始测试数据中的签名
            System.out.println("\n=== Test 5: Verify Java test_1 signature ===");
            String origSig = "3045022100c75cb782f822a99281d280bce9af156265252b60f1e28b74f34d1e4361c298a80220148a04be093709891f64484eb657fd54b1eab5c20c933b8133bdebe7dea4880f";
            boolean origVerified = SM2Util.verify(message, publicKey, origSig);
            System.out.println("Original test_1 sig verify: " + (origVerified ? "PASS" : "FAIL"));

        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    static byte[] buildDerSignature(byte[] r, byte[] s) {
        // DER encode: SEQUENCE { INTEGER r, INTEGER s }
        // INTEGER: 02 <len> <value> (prepend 0x00 if high bit set)
        byte[] intR = encodeInteger(r);
        byte[] intS = encodeInteger(s);
        int seqLen = intR.length + intS.length;

        byte[] der;
        int pos = 0;
        if (seqLen < 128) {
            der = new byte[2 + seqLen];
            der[pos++] = 0x30; // SEQUENCE
            der[pos++] = (byte) seqLen;
        } else if (seqLen < 256) {
            der = new byte[3 + seqLen];
            der[pos++] = 0x30;
            der[pos++] = (byte) 0x81;
            der[pos++] = (byte) seqLen;
        } else {
            throw new RuntimeException("Signature too long");
        }
        System.arraycopy(intR, 0, der, pos, intR.length);
        pos += intR.length;
        System.arraycopy(intS, 0, der, pos, intS.length);
        return der;
    }

    static byte[] encodeInteger(byte[] value) {
        // 计算需要前缀 0x00 的情况
        boolean needPad = (value[0] & 0x80) != 0;
        int len = value.length + (needPad ? 1 : 0);
        byte[] result = new byte[2 + len];
        result[0] = 0x02; // INTEGER tag
        result[1] = (byte) len;
        if (needPad) {
            result[2] = 0x00;
            System.arraycopy(value, 0, result, 3, value.length);
        } else {
            System.arraycopy(value, 0, result, 2, value.length);
        }
        return result;
    }
}
