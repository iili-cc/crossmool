import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;

/**
 * 不依赖 crossmool 的纯 BouncyCastle SM2 诊断
 * 直接使用 BC 底层 API 进行签名/验签，输出中间值
 */
public class SM2PureBCDiag {

    public static void main(String[] args) throws Exception {
        System.out.println("=== 纯 BouncyCastle SM2 诊断 ===\n");

        // 曲线
        SM2P256V1Curve curve = new SM2P256V1Curve();
        BigInteger n = curve.getOrder();
        BigInteger p = curve.getField().getCharacteristic();
        BigInteger a = curve.getA().toBigInteger();
        BigInteger b = curve.getB().toBigInteger();

        // 生成元点
        ECPoint G = curve.createPoint(
            new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
            new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
        );

        // 测试密钥
        BigInteger d = new BigInteger("72e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057", 16);
        ECPoint P = G.multiply(d).normalize();
        BigInteger pubX = P.getAffineXCoord().toBigInteger();
        BigInteger pubY = P.getAffineYCoord().toBigInteger();

        System.out.println("[1] 密钥");
        System.out.println("  d  = " + d.toString(16));
        System.out.println("  Px = " + pubX.toString(16));
        System.out.println("  Py = " + pubY.toString(16));

        // USER_ID
        String USER_ID = "1234567812345678";
        byte[] USER_ID_BYTES = USER_ID.getBytes(StandardCharsets.UTF_8);
        System.out.println("\n[2] USER_ID");
        System.out.println("  ID = " + USER_ID);
        System.out.println("  ID bytes hex = " + bytesToHex(USER_ID_BYTES));
        System.out.println("  ID bytes length = " + USER_ID_BYTES.length);

        // 测试消息
        String testMsg = "Hello SM2 Test!";
        byte[] msgBytes = testMsg.getBytes(StandardCharsets.UTF_8);
        System.out.println("\n[3] 测试消息");
        System.out.println("  msg = " + testMsg);
        System.out.println("  msg hex = " + bytesToHex(msgBytes));

        // 签名
        System.out.println("\n[4] BouncyCastle 签名");
        ECDomainParameters domainParams = new ECDomainParameters(curve, G, n);
        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(d, new ECNamedDomainParameters(GMObjectIdentifiers.sm2p256v1, domainParams));
        ECPublicKeyParameters pubParams = new ECPublicKeyParameters(P, new ECNamedDomainParameters(GMObjectIdentifiers.sm2p256v1, domainParams));

        ParametersWithID signParams = new ParametersWithID(privParams, USER_ID_BYTES);
        ParametersWithID verifyParams = new ParametersWithID(pubParams, USER_ID_BYTES);

        SM2Signer signer = new SM2Signer();
        signer.init(true, signParams);
        signer.update(msgBytes, 0, msgBytes.length);
        byte[] signature = signer.generateSignature();

        System.out.println("  sig DER = " + bytesToHex(signature));
        System.out.println("  sig len = " + signature.length);

        // 解析
        DLSequence seq = (DLSequence) DLSequence.getInstance(signature);
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();
        System.out.println("  r = " + r.toString(16));
        System.out.println("  s = " + s.toString(16));

        // 自验
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, verifyParams);
        verifier.update(msgBytes, 0, msgBytes.length);
        boolean selfVerify = verifier.verifySignature(signature);
        System.out.println("  自验: " + (selfVerify ? "PASS" : "FAIL"));

        // 输出公钥的原始编码
        System.out.println("\n[5] 公钥编码");
        byte[] pubEnc = P.getEncoded(false);
        System.out.println("  未压缩 (65B) = " + bytesToHex(pubEnc));

        // 曲线参数 32 字节大端
        System.out.println("\n[6] 曲线参数 (32B 大端)");
        System.out.println("  a  = " + toBytes32(a));
        System.out.println("  b  = " + toBytes32(b));
        System.out.println("  Gx = " + toBytes32(G.getAffineXCoord().toBigInteger()));
        System.out.println("  Gy = " + toBytes32(G.getAffineYCoord().toBigInteger()));
        System.out.println("  Px = " + toBytes32(pubX));
        System.out.println("  Py = " + toBytes32(pubY));

        // 保存供 Python 对比
        String output = "d=" + d.toString(16) + "\n";
        output += "Px=" + pubX.toString(16) + "\n";
        output += "Py=" + pubY.toString(16) + "\n";
        output += "msg=" + testMsg + "\n";
        output += "msg_hex=" + bytesToHex(msgBytes) + "\n";
        output += "sig=" + bytesToHex(signature) + "\n";
        output += "r=" + r.toString(16) + "\n";
        output += "s=" + s.toString(16) + "\n";
        output += "a=" + toBytes32(a) + "\n";
        output += "b=" + toBytes32(b) + "\n";
        output += "Gx=" + toBytes32(G.getAffineXCoord().toBigInteger()) + "\n";
        output += "Gy=" + toBytes32(G.getAffineYCoord().toBigInteger()) + "\n";
        output += "Px_32B=" + toBytes32(pubX) + "\n";
        output += "Py_32B=" + toBytes32(pubY) + "\n";
        output += "p=" + p.toString(16) + "\n";
        output += "n=" + n.toString(16) + "\n";

        java.nio.file.Files.write(
            java.nio.file.Paths.get("bc_pure_diag.txt"),
            output.getBytes(StandardCharsets.UTF_8)
        );
        System.out.println("\n已保存到 bc_pure_diag.txt");
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

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static String toBytes32(BigInteger val) {
        byte[] bytes = val.toByteArray();
        byte[] result = new byte[32];
        int copyStart = Math.max(0, bytes.length - 32);
        int copyLen = Math.min(32, bytes.length);
        System.arraycopy(bytes, copyStart, result, 32 - copyLen, copyLen);
        return bytesToHex(result);
    }
}
