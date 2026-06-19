package main
import("encoding/hex";"encoding/json";"fmt";"io";"os";cc "cc.iili.tools/crossmool")
func main(){data,_:=io.ReadAll(os.Stdin);var ref map[string]interface{};json.Unmarshal(data,&ref)
r:=map[string]string{}
if cs,ok:=ref["cross_enc"].(string);ok&&cs!=""{d,err:=cc.Decrypt(cs,"308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356")
if err!=nil{r["enc"]="FAIL:"+err.Error()}else if d=="Hello, 这是跨语言国密互通性测试数据"{r["enc"]="PASS"}else{r["enc"]="FAIL"}}
if ss,ok:=ref["cross_sig"].(string);ok&&ss!=""{ok,_:=cc.Verify("Hello, 这是跨语言国密互通性测试数据","3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",ss)
if ok{r["sig"]="PASS"}else{r["sig"]="FAIL"}}
if sc,ok:=ref["cross_sm4"].(string);ok&&sc!=""{sk,_:=hex.DecodeString("0123456789abcdeffedcba9876543210")
sd,err:=cc.DecryptGcmToString(sk,sc)
if err!=nil{r["sm4"]="FAIL:"+err.Error()}else if sd=="Hello, 这是跨语言国密互通性测试数据"{r["sm4"]="PASS"}else{r["sm4"]="FAIL"}}
if cs2,ok:=ref["cross_enc"].(string);ok&&cs2!=""{if ss2,ok:=ref["cross_sig"].(string);ok&&ss2!=""{
d2,_:=cc.Decrypt(cs2,"308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356");ok2,_:=cc.Verify(d2,"3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",ss2)
if d2=="Hello, 这是跨语言国密互通性测试数据"&&ok2{r["esvd"]="PASS"}else{r["esvd"]="FAIL"}}}
o,_:=json.Marshal(r);fmt.Print(string(o))}