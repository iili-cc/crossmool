package main
import ("encoding/hex";"encoding/json";"fmt";crossmool "cc.iili.tools/crossmool")
const MSG = "Hello, 这是跨语言国密互通性测试数据"
const SM4_KEY = "0123456789abcdeffedcba9876543210"
const HMAC_KEY = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
const EXP_SM3 = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
const EXP_SM3_HMAC = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"
var DK = map[string]string{
    "enc_pub_der": "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
    "enc_priv_der": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
    "sig_pub_der": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
    "sig_priv_der": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
}
func main() {
    r := map[string]interface{}{"lang": "go"}
    c, err := crossmool.Encrypt(MSG, DK["enc_pub_der"], false)
    if err != nil { r["sm2_enc_dec"] = "FAIL: " + err.Error()
    } else {
        r["sm2_enc"] = c
        d, err := crossmool.Decrypt(c, DK["enc_priv_der"])
        if err != nil { r["sm2_enc_dec"] = "FAIL: " + err.Error()
        } else if d == MSG { r["sm2_enc_dec"] = "PASS" } else { r["sm2_enc_dec"] = "FAIL" }
    }
    s, err := crossmool.Sign(MSG, DK["sig_priv_der"], false)
    if err != nil { r["sm2_sig_ver"] = "FAIL: " + err.Error()
    } else {
        r["sm2_sig"] = s
        ok, _ := crossmool.Verify(MSG, DK["sig_pub_der"], s)
        if ok { r["sm2_sig_ver"] = "PASS" } else { r["sm2_sig_ver"] = "FAIL" }
    }
    h := crossmool.DigestToStr(MSG, false)
    r["sm3_hash"] = h
    if h == EXP_SM3 { r["sm3"] = "PASS" } else { r["sm3"] = "FAIL" }
    hm, _ := crossmool.HMACToStr(HMAC_KEY, MSG, false)
    r["sm3_hmac_hash"] = hm
    if hm == EXP_SM3_HMAC { r["sm3_hmac"] = "PASS" } else { r["sm3_hmac"] = "FAIL" }
    sk, _ := hex.DecodeString(SM4_KEY)
    sc, err := crossmool.EncryptGcm(sk, []byte(MSG), false)
    if err != nil { r["sm4_enc_dec"] = "FAIL: " + err.Error()
    } else {
        r["sm4_enc"] = sc
        sd, err := crossmool.DecryptGcmToString(sk, sc)
        if err != nil { r["sm4_enc_dec"] = "FAIL: " + err.Error()
        } else if sd == MSG { r["sm4_enc_dec"] = "PASS" } else { r["sm4_enc_dec"] = "FAIL" }
    }
    r["cross"] = map[string]interface{}{"lang":"go","msg":MSG,"sm2_enc":r["sm2_enc"],"sm2_sig":r["sm2_sig"],"sm4_enc":r["sm4_enc"],"sm3_hash":r["sm3_hash"],"sm3_hmac_hash":r["sm3_hmac_hash"]}
    o, _ := json.Marshal(r)
    fmt.Println(string(o))
}
