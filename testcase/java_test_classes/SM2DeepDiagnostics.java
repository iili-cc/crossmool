import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.util.SM2KeyUtil;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;

public class SM2DeepDiagnostics {

    private static final String USER_ID = "1234567812345678";
    private static final byte[] USER_ID_BYTES = USER_ID.getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args) throws Exception {
        System.out.println("=== BouncyCastle SM2Signer 深度诊断 ===\n");

        String privateKeyHex = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        String publicKeyHex = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";

        byte[] privateKeyBytes = hexToBytes(privateKeyHex);
        byte[] publicKeyBytes = hexToBytes(publicKeyHex);

        // 1. 曲线参数
        System.out.println("[1] BouncyCastle 曲线参数");
        SM2P256V1Curve curve = new SM2P256V1Curve();
        BigInteger p = curve.getField().getCharacteristic();
        BigInteger a = curve.getA().toBigInteger();
        BigInteger b = curve.getB().toBigInteger();
        BigInteger n = curve.getOrder();
        ECPoint G = curve.createPoint(
            new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
            new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
        );
        BigInteger Gx = G.getAffineXCoord().toBigInteger();
        BigInteger Gy = G.getAffineYCoord().toBigInteger();

        System.out.println("  p  = " + p.toString(16));
        System.out.println("  a  = " + a.toString(16));
        System.out.println("  b  = " + b.toString(16));
        System.out.println("  n  = " + n.toString(16));
        System.out.println("  Gx = " + Gx.toString(16));
        System.out.println("  Gy = " + Gy.toString(16));

        // 2. 密钥参数
        System.out.println("\n[2] 密钥参数");
        ECPrivateKeyParameters privParams = SM2KeyUtil.convertPKCS8BytesToECPrivateKeyParameters(privateKeyBytes);
        ECPublicKeyParameters pubParams = SM2KeyUtil.convertX509BytesToECPublicKeyParameters(publicKeyBytes);

        BigInteger d = privParams.getD();
        ECPoint pubPoint = pubParams.getQ();
        BigInteger pubX = pubPoint.getAffineXCoord().toBigInteger();
        BigInteger pubY = pubPoint.getAffineYCoord().toBigInteger();

        System.out.println("  d  = " + d.toString(16));
        System.out.println("  Px = " + pubX.toString(16));
        System.out.println("  Py = " + pubY.toString(16));

        // 验证 d*G == P
        ECPoint dG = G.multiply(d).normalize();
        System.out.println("  d*G.X = " + dG.getAffineXCoord().toBigInteger().toString(16));
        System.out.println("  d*G.Y = " + dG.getAffineYCoord().toBigInteger().toString(16));
        System.out.println("  d*G == P: " + dG.equals(pubPoint));

        // 3. OID
        System.out.println("\n[3] SM2 OID");
        System.out.println("  sm2p256v1 OID: " + GMObjectIdentifiers.sm2p256v1);
        System.out.println("  sm2sign OID:   " + GMObjectIdentifiers.sm2sign_with_sm3);

        // 4. 签名测试
        System.out.println("\n[4] 签名测试");
        String testMsg = "Hello SM2 Test!";
        String sigHex = SM2Util.signToHex(testMsg, privateKeyHex);
        byte[] sig = hexToBytes(sigHex);
        System.out.println("  签名 DER: " + sigHex);
        System.out.println("  签名长度: " + sig.length + " 字节");

        // 解析签名
        DLSequence seq = (DLSequence) DLSequence.getInstance(sig);
        ASN1Integer rASN = (ASN1Integer) seq.getObjectAt(0);
        ASN1Integer sASN = (ASN1Integer) seq.getObjectAt(1);
        BigInteger r = rASN.getValue();
        BigInteger s = sASN.getValue();
        System.out.println("  r = " + r.toString(16));
        System.out.println("  s = " + s.toString(16));

        // 自验
        boolean selfVerify = SM2Util.verify(testMsg, publicKeyHex, sigHex);
        System.out.println("  自验: " + (selfVerify ? "PASS" : "FAIL"));

        // 5. 输出曲线参数 32 字节大端序
        System.out.println("\n[5] 曲线参数 (32字节大端序)");
        System.out.println("  a  (32B) = " + toBytes32(a));
        System.out.println("  b  (32B) = " + toBytes32(b));
        System.out.println("  Gx (32B) = " + toBytes32(Gx));
        System.out.println("  Gy (32B) = " + toBytes32(Gy));
        System.out.println("  Px (32B) = " + toBytes32(pubX));
        System.out.println("  Py (32B) = " + toBytes32(pubY));

        // 6. 公钥编码
        System.out.println("\n[6] 公钥编码");
        byte[] pubEncoded = pubPoint.getEncoded(false);
        System.out.println("  未压缩 (65B): " + bytesToHex(pubEncoded));
        System.out.println("  04 前缀: " + String.format("%02x", pubEncoded[0]));
        byte[] xBytes = new byte[32];
        byte[] yBytes = new byte[32];
        System.arraycopy(pubEncoded, 1, xBytes, 0, 32);
        System.arraycopy(pubEncoded, 33, yBytes, 0, 32);
        System.out.println("  Px = " + bytesToHex(xBytes));
        System.out.println("  Py = " + bytesToHex(yBytes));

        // 保存结果
        String output = "p=" + p.toString(16) + "\n";
        output += "a=" + a.toString(16) + "\n";
        output += "b=" + b.toString(16) + "\n";
        output += "n=" + n.toString(16) + "\n";
        output += "Gx=" + Gx.toString(16) + "\n";
        output += "Gy=" + Gy.toString(16) + "\n";
        output += "d=" + d.toString(16) + "\n";
        output += "Px=" + pubX.toString(16) + "\n";
        output += "Py=" + pubY.toString(16) + "\n";
        output += "dG_eq_P=" + dG.equals(pubPoint) + "\n";
        output += "a_32B=" + toBytes32(a) + "\n";
        output += "Px_32B=" + bytesToHex(xBytes) + "\n";
        output += "Py_32B=" + bytesToHex(yBytes) + "\n";
        output += "r=" + r.toString(16) + "\n";
        output += "s=" + s.toString(16) + "\n";

        java.nio.file.Files.write(
            java.nio.file.Paths.get("bc_diag_output.txt"),
            output.getBytes(StandardCharsets.UTF_8)
        );
        System.out.println("\n诊断数据已保存到 bc_diag_output.txt");
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
