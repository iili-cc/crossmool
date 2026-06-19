package main
import("encoding/hex";"encoding/json";"fmt";"strings";cc "cc.iili.tools/crossmool")
var esc=strings.ReplaceAll
func main(){r:=map[string]string{}
sk,_:=hex.DecodeString("0123456789abcdeffedcba9876543210")
c,_:=cc.Encrypt("Hello, 这是跨语言国密互通性测试数据","3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",false);d,_:=cc.Decrypt(c,"308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356")
r["enc"]=func()string{if d=="Hello, 这是跨语言国密互通性测试数据"{return"PASS"};return"FAIL"}()
r["cross_enc"]=esc(esc(esc(c,"\\","\\\\"),"\"","\\\""),"\n","\\n")
s,_:=cc.Sign("Hello, 这是跨语言国密互通性测试数据","308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",false);ok,_:=cc.Verify("Hello, 这是跨语言国密互通性测试数据","3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",s)
r["sig"]=func()string{if ok{return"PASS"};return"FAIL"}()
r["cross_sig"]=esc(esc(esc(s,"\\","\\\\"),"\"","\\\""),"\n","\\n")
c2,_:=cc.Encrypt("Hello, 这是跨语言国密互通性测试数据","3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",false);s2,_:=cc.Sign("Hello, 这是跨语言国密互通性测试数据","308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",false)
d2,_:=cc.Decrypt(c2,"308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356");ok2,_:=cc.Verify(d2,"3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",s2)
r["esvd"]=func()string{if d2=="Hello, 这是跨语言国密互通性测试数据"&&ok2{return"PASS"};return"FAIL"}()
r["sm3"]=func()string{if cc.DigestToStr("Hello, 这是跨语言国密互通性测试数据",false)=="0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"{return"PASS"};return"FAIL"}()
hm,_:=cc.HMACToStr("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20","Hello, 这是跨语言国密互通性测试数据",false)
r["hmac"]=func()string{if hm=="3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"{return"PASS"};return"FAIL"}()
sc,_:=cc.EncryptGcm(sk,[]byte("Hello, 这是跨语言国密互通性测试数据"),false);sd,_:=cc.DecryptGcmToString(sk,sc)
r["sm4"]=func()string{if sd=="Hello, 这是跨语言国密互通性测试数据"{return"PASS"};return"FAIL"}()
r["cross_sm4"]=esc(esc(esc(sc,"\\","\\\\"),"\"","\\\""),"\n","\\n")
o,_:=json.Marshal(r);fmt.Print(string(o))}