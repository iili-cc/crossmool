package main
import ("encoding/json";"fmt";"os";crossmool "cc.iili.tools/crossmool")
var D=map[string]string{"msg": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e", "sm2_enc_priv": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", "sm2_enc_pub": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sm2_sig_priv": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3", "sm2_sig_pub": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sm4_key": "0123456789abcdeffedcba9876543210", "sm4_iv": "000102030405060708090a0b", "hmac_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}
var EXP=map[string]string{"sm3": "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b", "sm3_hmac": "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"}
var MSG="Hello, 这是跨语言国密互通性测试数据"
func main(){r:=map[string]any{}
d:=crossmool.DigestToStr(MSG,false);r["sm3"]=d;r["sm3_ok"]=(d==EXP["sm3"])
h,_:=crossmool.HMACToStr(D["hmac_key"],MSG,false);r["sm3_hmac"]=h;r["sm3_hmac_ok"]=(h==EXP["sm3_hmac"])
c,_:=crossmool.Encrypt(MSG,D["sm2_enc_pub"],false);r["sm2_enc"]=c
s,_:=crossmool.Sign(MSG,D["sm2_sig_priv"],false);r["sm2_sig"]=s
_=s
sm4Key,_:=crossmool.DecodeHexString(D["sm4_key"])
sm4,_:=crossmool.EncryptGcm(sm4Key,[]byte(MSG),false);r["sm4_enc"]=sm4
if len(os.Args)>1{var ref map[string]any
b,_:=os.ReadFile(os.Args[1]);json.Unmarshal(b,&ref)
if cs,ok:=ref["sm2_enc"].(string);ok{
dec,_:=crossmool.Decrypt(cs,D["sm2_enc_priv"])
r["sm2_dec_ok"]=(dec==MSG)}
if ss,ok:=ref["sm2_sig"].(string);ok{
ok,_:=crossmool.Verify(MSG,D["sm2_sig_pub"],ss)
r["sm2_ver_ok"]=ok}
if es,ok:=ref["sm2_enc_sign"].(map[string]any);ok{
cs,_:=es["cipher"].(string);ss,_:=es["sig"].(string)
ok,_:=crossmool.Verify(cs,D["sm2_sig_pub"],ss)
dec,_:=crossmool.Decrypt(cs,D["sm2_enc_priv"])
r["sm2_esvd_ok"]=(ok&&dec==MSG)}
if sm,ok:=ref["sm4_enc"].(string);ok{
sk,_:=crossmool.DecodeHexString(D["sm4_key"])
dec,_:=crossmool.DecryptGcmToString(sk,sm)
r["sm4_dec_ok"]=(dec==MSG)}
}
o,_:=json.Marshal(r);fmt.Println(string(o))}