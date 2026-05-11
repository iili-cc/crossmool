import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;

public class Sm4DirectTest {
    public static void main(String[] args) throws Exception {
        byte[] key = HexUtil.decodeHexStr("8091d00c09ba74cfe6da26b7daa7ce39");

        // Read ciphertext from file (first arg or default)
        String ctPath = args.length > 0 ? args[0] : ".interop_temp/ct_hex.txt";
        String ct = new String(Files.readAllBytes(Paths.get(ctPath)), StandardCharsets.UTF_8).trim();

        System.out.println("CT len: " + ct.length());
        System.out.println("CT: " + ct.substring(0, Math.min(40, ct.length())) + "...");

        String pt = SM4Util.decryptEcbNative(key, ct);
        System.out.println("PT: [" + pt + "]");
        System.out.println("PT bytes: " + HexUtil.encodeHexStr(pt.getBytes(StandardCharsets.UTF_8)));

        String expected = "国密算法跨语言互通测试：简体中文";
        byte[] expBytes = expected.getBytes(StandardCharsets.UTF_8);
        System.out.println("EXP bytes: " + HexUtil.encodeHexStr(expBytes));
        System.out.println("Match: " + pt.equals(expected));
    }
}
