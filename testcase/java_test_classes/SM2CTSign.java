import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.gm.SM2P256V1Curve;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;

/**
 * 对密文字符串签名，输出所有中间数据供 C/Python 对比
 */
public class SM2CTSign {
    public static void main(String[] args) throws Exception {
        SM2P256V1Curve curve = new SM2P256V1Curve();
        BigInteger n = curve.getOrder();
        BigInteger d = new BigInteger("72e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057", 16);
        ECPoint G = curve.createPoint(
            new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
            new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
        );
        ECPoint P = G.multiply(d).normalize();
        String USER_ID = "1234567812345678";
        byte[] USER_ID_BYTES = USER_ID.getBytes(StandardCharsets.UTF_8);

        // 密文字符串 (和 test_1_simple_text.json 中一样)
        String ct = "046a2146cffa0e592b74f49304a75eb73449be5ae5f7cabac4a3938ae34539207472a2b912701a096ad7182772cede4439cc0642c3b56d123ca9c8b11b569ab94197d41b436a9240ef89ed76d01bee13129c5abc6aefa0d262424f147382f478fae20b93b2b671f0a33eec6a00830f44a191";
        byte[] ctBytes = ct.getBytes(StandardCharsets.UTF_8);

        // 用纯 BC 签名 (不经过 crossmool 的 SM2Util)
        ECDomainParameters domainParams = new ECDomainParameters(curve, G, n);
        ECPrivateKeyParameters privParams = new ECPrivateKeyParameters(d, new ECNamedDomainParameters(GMObjectIdentifiers.sm2p256v1, domainParams));
        ECPublicKeyParameters pubParams = new ECPublicKeyParameters(P, new ECNamedDomainParameters(GMObjectIdentifiers.sm2p256v1, domainParams));

        ParametersWithID signParams = new ParametersWithID(privParams, USER_ID_BYTES);
        ParametersWithID verifyParams = new ParametersWithID(pubParams, USER_ID_BYTES);

        SM2Signer signer = new SM2Signer();
        signer.init(true, signParams);
        signer.update(ctBytes, 0, ctBytes.length);
        byte[] signature = signer.generateSignature();

        // 解析
        DLSequence seq = (DLSequence) DLSequence.getInstance(signature);
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getValue();

        // 自验
        SM2Signer verifier = new SM2Signer();
        verifier.init(false, verifyParams);
        verifier.update(ctBytes, 0, ctBytes.length);
        boolean selfVerify = verifier.verifySignature(signature);

        System.out.println("=== BC 纯签名 (密文字符串) ===");
        System.out.println("Px = " + P.getAffineXCoord().toBigInteger().toString(16));
        System.out.println("Py = " + P.getAffineYCoord().toBigInteger().toString(16));
        System.out.println("ct len = " + ctBytes.length);
        System.out.println("sig DER = " + bytesToHex(signature));
        System.out.println("r = " + r.toString(16));
        System.out.println("s = " + s.toString(16));
        System.out.println("self-verify = " + selfVerify);

        // 保存供 Python/C 使用
        String output = "Px=" + P.getAffineXCoord().toBigInteger().toString(16) + "\n";
        output += "Py=" + P.getAffineYCoord().toBigInteger().toString(16) + "\n";
        output += "d=" + d.toString(16) + "\n";
        output += "ct_hex_str=" + ct + "\n";
        output += "ct_bytes_len=" + ctBytes.length + "\n";
        output += "sig=" + bytesToHex(signature) + "\n";
        output += "r=" + r.toString(16) + "\n";
        output += "s=" + s.toString(16) + "\n";
        output += "user_id=" + USER_ID + "\n";
        output += "user_id_hex=" + bytesToHex(USER_ID_BYTES) + "\n";
        output += "ct_bytes_hex=" + bytesToHex(ctBytes) + "\n";

        java.nio.file.Files.write(
            java.nio.file.Paths.get("bc_ct_sign.txt"),
            output.getBytes(StandardCharsets.UTF_8)
        );
        System.out.println("\n已保存到 bc_ct_sign.txt");
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
