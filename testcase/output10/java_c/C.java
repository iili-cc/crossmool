import java.nio.charset.StandardCharsets;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;
import java.nio.file.*;
public class C{static String M="Hello, 这是跨语言国密互通性测试数据",SK="0123456789abcdeffedcba9876543210",EPR="308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",SP="3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
public static void main(String[]a)throws Exception{
String js=Files.readString(Path.of(a[0]));
cs=ext(js,"x_enc");ss=ext(js,"x_sig");sc=ext(js,"x_sm4");
System.out.print("{");boolean f=true;
if(!cs.isEmpty()){try{String d=SM2Util.decrypt(cs,EPR);if(f)f=false;else System.out.print(",");System.out.print("\"enc\":\""+(d.equals(M)?"PASS":"FAIL")+"\"");}catch(Exception e){if(f)f=false;else System.out.print(",");System.out.print("\"enc\":\"FAIL\"");}}
if(!ss.isEmpty()){try{boolean ok=SM2Util.verify(M,SP,ss);if(f)f=false;else System.out.print(",");System.out.print("\"sig\":\""+(ok?"PASS":"FAIL")+"\"");}catch(Exception e){if(f)f=false;else System.out.print(",");System.out.print("\"sig\":\"FAIL\"");}}
if(!sc.isEmpty()){try{byte[] sk=HexUtil.decodeHexStr(SK);String sd=SM4Util.decrypt(sk,sc);if(f)f=false;else System.out.print(",");System.out.print("\"sm4\":\""+(sd.equals(M)?"PASS":"FAIL")+"\"");}catch(Exception e){if(f)f=false;else System.out.print(",");System.out.print("\"sm4\":\"FAIL\"");}}
if(!cs.isEmpty()&&!ss.isEmpty()){try{String d2=SM2Util.decrypt(cs,EPR);boolean ok2=SM2Util.verify(d2,SP,ss);if(f)f=false;else System.out.print(",");System.out.print("\"esvd\":\""+(d2.equals(M)&&ok2?"PASS":"FAIL")+"\"");}catch(Exception e){if(f)f=false;else System.out.print(",");System.out.print("\"esvd\":\"FAIL\"");}}
System.out.println("}");}
static String ext(String json,String key){String s="\""+key+"\":\"";int i=json.indexOf(s);if(i<0){s="\""+key+"\": \"";i=json.indexOf(s);}
if(i<0)return"";i+=s.length();
StringBuilder sb=new StringBuilder();boolean es=false;
for(;i<json.length();i++){char c=json.charAt(i);
if(es){sb.append(c);es=false;}else if(c=='\\'){es=true;}else if(c=='"'){break;}else{sb.append(c);}}
return sb.toString();}
static String cs,ss,sc;
}