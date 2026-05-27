import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.util.SM2KeyUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.util.encoders.Hex;
import java.security.Security;
import java.nio.charset.StandardCharsets;

public class JavaSignTest {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        
        String signPrivKeyHex = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        String signPubKeyHex = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
        
        byte[] privBytes = Hex.decode(signPrivKeyHex);
        byte[] pubBytes = Hex.decode(signPubKeyHex);
        byte[] msgBytes = "hello".getBytes("UTF-8");
        byte[] userId = "1234567812345678".getBytes(StandardCharsets.UTF_8);
        
        // Replicate getSM2Signer logic EXACTLY
        byte[] signKeyBytes = SM2KeyUtil.convertStringToBytes(signPrivKeyHex);
        System.out.println("signKeyBytes == privBytes: " + java.util.Arrays.equals(signKeyBytes, privBytes));
        
        ECPrivateKeyParameters privateKeyParameters = SM2KeyUtil.convertPKCS8BytesToECPrivateKeyParameters(signKeyBytes);
        ParametersWithID privateParam = new ParametersWithID(privateKeyParameters, userId);
        SM2Signer sm2Signer = new SM2Signer();
        sm2Signer.init(true, privateParam);
        sm2Signer.update(msgBytes, 0, msgBytes.length);
        byte[] sigReplicated = sm2Signer.generateSignature();
        System.out.println("Replicated sig: " + Hex.toHexString(sigReplicated));
        
        // Now use SM2Util.sign
        byte[] sigFromUtil = SM2Util.sign(msgBytes, privBytes);
        System.out.println("SM2Util sig: " + Hex.toHexString(sigFromUtil));
        
        // Are they the same?
        System.out.println("Same sig: " + java.util.Arrays.equals(sigReplicated, sigFromUtil));
        
        // Verify replicated sig with manual verifier
        ECPublicKeyParameters pubKey = SM2KeyUtil.convertX509BytesToECPublicKeyParameters(pubBytes);
        SM2Signer v1 = new SM2Signer();
        v1.init(false, new ParametersWithID(pubKey, userId));
        v1.update(msgBytes, 0, msgBytes.length);
        System.out.println("\nManual verify replicated sig: " + v1.verifySignature(sigReplicated));
        
        // Verify SM2Util sig with manual verifier
        SM2Signer v2 = new SM2Signer();
        v2.init(false, new ParametersWithID(pubKey, userId));
        v2.update(msgBytes, 0, msgBytes.length);
        System.out.println("Manual verify SM2Util sig: " + v2.verifySignature(sigFromUtil));
        
        // Verify replicated sig with SM2Util.verify
        boolean utilVerifyReplicated = SM2Util.verify(msgBytes, sigReplicated, pubBytes);
        System.out.println("SM2Util verify replicated sig: " + utilVerifyReplicated);
        
        // Let's check if the issue is that SM2Util.sign uses a DIFFERENT code path
        // SM2Util.sign(byte[], byte[]) calls getSM2Signer(true, privateKey)
        // getSM2Signer(true, byte[]) uses SM2KeyUtil.convertPKCS8BytesToECPrivateKeyParameters
        // which is the SAME as what we're doing...
        
        // Wait - let me check if the compiled jar is up to date!
        // The jar was built at 21:18, but the source might have been modified after
        System.out.println("\n=== Checking jar timestamp ===");
        java.io.File jarFile = new java.io.File("../java/crossmool/target/crossmool-1.1.0.jar");
        System.out.println("Jar last modified: " + new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(jarFile.lastModified())));
        
        java.io.File srcFile = new java.io.File("../java/crossmool/src/main/java/cc/iili/tools/crossmool/tool/SM2Util.java");
        System.out.println("Src last modified: " + new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date(srcFile.lastModified())));
    }
}
