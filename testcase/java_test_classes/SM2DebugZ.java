package testcase;

import cc.iili.tools.crossmool.util.SM2KeyUtil;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 调试 Java SM2Signer 的 Z 值计算和哈希，与 GmSSL/Python 对比
 */
public class SM2DebugZ {
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    static final String USER_ID = "1234567812345678";
    static final byte[] USER_ID_BYTES = USER_ID.getBytes(StandardCharsets.UTF_8);

    // 测试数据
    static final String CT_HEX = "04e4534be6847921acdf2f0ff2e4d1e0057bcdba9450c64af197c30762e8356531a26295dfbfc6335d21ad8176312e8c9b0489400599657c6eacf197f08db43a35d96c52a989a8aab3f9b855a56bb507e5ebe81f2aea88d76d72671a3bd1244273f80dd60d50556bb4e5cff5fc6a02b97fdf";
    static final String SIG_HEX = "3046022100cae388164ba6e735814a03e7cff2a09fa017db831a2ad932b9c2a226776fe07f022100dde7ae2b5c0a32ff04c89d5ebe85911d5015d2593eb012ca66caa5d5ef4e6686";
    static final String SIGN_PUBKEY_HEX = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
    static final String DEC_PRIVKEY_HEX = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] sm3Hash(byte[] data) {
        SM3Digest digest = new SM3Digest();
        digest.update(data, 0, data.length);
        byte[] result = new byte[32];
        digest.doFinal(result, 0);
        return result;
    }

    /**
     * 手动计算 SM2 Z 值
     * Z = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)
     */
    public static byte[] computeZ(ECPoint publicPoint, ECDomainParameters params) {
        SM3Digest sm3 = new SM3Digest();

        // ENTL: ID length in bits, big-endian 2 bytes
        int idLen = USER_ID_BYTES.length * 8;
        byte[] entl = new byte[]{(byte)(idLen >> 8), (byte)(idLen & 0xff)};
        sm3.update(entl, 0, 2);

        // ID
        sm3.update(USER_ID_BYTES, 0, USER_ID_BYTES.length);

        // a (coefficient)
        byte[] a = params.getCurve().getA().getEncoded();
        sm3.update(a, 0, a.length);
        System.out.println("a (" + a.length + " bytes): " + bytesToHex(a));

        // b (coefficient)
        byte[] b = params.getCurve().getB().getEncoded();
        sm3.update(b, 0, b.length);
        System.out.println("b (" + b.length + " bytes): " + bytesToHex(b));

        // Gx (generator x)
        byte[] gxBytes = params.getG().getRawXCoord().getEncoded();
        sm3.update(gxBytes, 0, gxBytes.length);
        System.out.println("Gx (" + gxBytes.length + " bytes): " + bytesToHex(gxBytes));

        // Gy (generator y)
        byte[] gyBytes = params.getG().getRawYCoord().getEncoded();
        sm3.update(gyBytes, 0, gyBytes.length);
        System.out.println("Gy (" + gyBytes.length + " bytes): " + bytesToHex(gyBytes));

        // Px (public key x)
        byte[] pxBytes = publicPoint.getRawXCoord().getEncoded();
        sm3.update(pxBytes, 0, pxBytes.length);
        System.out.println("Px (" + pxBytes.length + " bytes): " + bytesToHex(pxBytes));

        // Py (public key y)
        byte[] pyBytes = publicPoint.getRawYCoord().getEncoded();
        sm3.update(pyBytes, 0, pyBytes.length);
        System.out.println("Py (" + pyBytes.length + " bytes): " + bytesToHex(pyBytes));

        byte[] z = new byte[32];
        sm3.doFinal(z, 0);
        return z;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== SM2 Z 值调试 ===");

        // 获取曲线参数
        X9ECParameters x9 = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domainParams = new ECDomainParameters(x9);

        System.out.println("\n曲线参数:");
        System.out.println("n = " + domainParams.getN().toString(16));
        byte[] gxFull = x9.getG().getRawXCoord().getEncoded();
        byte[] gyFull = x9.getG().getRawYCoord().getEncoded();
        System.out.println("Gx = " + bytesToHex(gxFull));
        System.out.println("Gy = " + bytesToHex(gyFull));

        // 解析公钥
        ECPublicKeyParameters pubKeyParams = SM2KeyUtil.convertX509BytesToECPublicKeyParameters(hexToBytes(SIGN_PUBKEY_HEX));
        ECPoint Q = pubKeyParams.getQ();
        System.out.println("\n公钥坐标:");
        System.out.println("Px = " + bytesToHex(Q.getRawXCoord().getEncoded()));
        System.out.println("Py = " + bytesToHex(Q.getRawYCoord().getEncoded()));

        // 计算 Z 值
        System.out.println("\n=== Z 值计算 ===");
        byte[] z = computeZ(Q, domainParams);
        System.out.println("\nZ = " + bytesToHex(z));

        // 签名内容
        byte[] contentBytes = CT_HEX.getBytes(StandardCharsets.UTF_8);
        System.out.println("\n内容 (" + contentBytes.length + " bytes): " + CT_HEX.substring(0, 20) + "...");

        // SM3(Z || content)
        byte[] hashInput = new byte[32 + contentBytes.length];
        System.arraycopy(z, 0, hashInput, 0, 32);
        System.arraycopy(contentBytes, 0, hashInput, 32, contentBytes.length);
        byte[] dgst = sm3Hash(hashInput);
        System.out.println("SM3(Z || content) = " + bytesToHex(dgst));

        // 用 SM2Signer 验签
        System.out.println("\n=== SM2Signer 验签 ===");
        SM2Signer signer = new SM2Signer();
        ParametersWithID pubParam = new ParametersWithID(pubKeyParams, USER_ID_BYTES);
        signer.init(false, pubParam);
        signer.update(contentBytes, 0, contentBytes.length);
        
        byte[] sigBytes = hexToBytes(SIG_HEX);
        boolean verifyResult = signer.verifySignature(sigBytes);
        System.out.println("SM2Signer.verifySignature: " + verifyResult);

        // 用自己签名，然后验签
        System.out.println("\n=== 自签自验 ===");
        ECPrivateKeyParameters privKeyParams = SM2KeyUtil.convertPKCS8BytesToECPrivateKeyParameters(hexToBytes(DEC_PRIVKEY_HEX));
        SM2Signer signerSign = new SM2Signer();
        ParametersWithID privParam = new ParametersWithID(privKeyParams, USER_ID_BYTES);
        signerSign.init(true, privParam);
        signerSign.update(contentBytes, 0, contentBytes.length);
        byte[] newSig = signerSign.generateSignature();
        System.out.println("新签名 (" + newSig.length + " bytes): " + bytesToHex(newSig));

        // 自验
        SM2Signer signerVerify = new SM2Signer();
        signerVerify.init(false, pubParam);
        signerVerify.update(contentBytes, 0, contentBytes.length);
        boolean selfVerify = signerVerify.verifySignature(newSig);
        System.out.println("自签自验结果: " + selfVerify);

        // 用 SM2Signer 验证原始 Java 签名 (来自 test_1_simple_text.json)
        System.out.println("\n=== 验证 JSON 中保存的 Java 签名 ===");
        SM2Signer signerV2 = new SM2Signer();
        signerV2.init(false, pubParam);
        signerV2.update(contentBytes, 0, contentBytes.length);
        boolean v2 = signerV2.verifySignature(sigBytes);
        System.out.println("验证 JSON 签名: " + v2);
    }
}
