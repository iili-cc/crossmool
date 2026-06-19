import cc.iili.tools.crossmool.tool.SM3Util;
public class SM3Check {
    public static void main(String[] args) {
        String msg1 = "Hello, 这是跨语言国密互通性测试数据";
        System.out.println("msg1 hash: " + SM3Util.digestToStr(msg1, false));
        System.out.println("expected:  0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b");
    }
}
