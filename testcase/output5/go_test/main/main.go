package main
import("encoding/json";"fmt";crossmool "cc.iili.tools/crossmool")
var MSG="Hello, 这是跨语言国密互通性测试数据"
var DK=map[string]string{"enc_pub_der": "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "enc_priv_der": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sig_pub_der": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sig_priv_der": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"}
var TD=map[string]string{"msg": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e", "enc_priv": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", "enc_pub": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sig_priv": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3", "sig_pub": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sm4_key": "0123456789abcdeffedcba9876543210", "hmac_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}
func main(){r:=map[string]any{}
c,_:=crossmool.Encrypt(MSG,DK["enc_pub_der"],false);r["sm2_enc"]=c
d,_:=crossmool.Decrypt(c,DK["enc_priv_der"]);r["sm2_enc_dec"]=(d==MSG)
s,_:=crossmool.Sign(MSG,DK["sig_priv_der"],false);r["sm2_sig"]=s
ok,_:=crossmool.Verify(MSG,DK["sig_pub_der"],s);r["sm2_sig_ver"]=ok
r["sm3_hash"]=crossmool.DigestToStr(MSG,false)
h,_:=crossmool.HMACToStr(TD["hmac_key"],MSG,false);r["sm3_hmac_hash"]=h
sk,_:=crossmool.DecodeHexString(TD["sm4_key"])
sc,_:=crossmool.EncryptGcm(sk,[]byte(MSG),false);r["sm4_enc"]=sc
sd,_:=crossmool.DecryptGcmToString(sk,sc);r["sm4_enc_dec"]=(sd==MSG)
r["cross"]=map[string]any{"sm2_enc":c,"sm2_sig":s,"sm4_enc":sc,"sm3_hash":r["sm3_hash"],"sm3_hmac_hash":r["sm3_hmac_hash"]}
o,_:=json.Marshal(r);fmt.Println(string(o))}