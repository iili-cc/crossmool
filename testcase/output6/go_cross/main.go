package main

import (
        "encoding/hex"
        "encoding/json"
        "fmt"
        "io"
        "os"
        crossmool "cc.iili.tools/crossmool"
)

const MSG = "Hello, 这是跨语言国密互通性测试数据"
const SM4_KEY = "0123456789abcdeffedcba9876543210"

var DK = map[string]string{
        "enc_priv_der": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
        "sig_pub_der":  "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
}

func main() {
        data, _ := io.ReadAll(os.Stdin)
        var ref map[string]interface{}
        json.Unmarshal(data, &ref)
        r := map[string]interface{} {"lang": "go", "consumer_of": ref["lang"]}

        if cs, ok := ref["sm2_enc"].(string); ok && cs != "" {
                d, err := crossmool.Decrypt(cs, DK["enc_priv_der"])
                if err != nil { r["sm2_dec"] = "FAIL: " + err.Error() } else if d == MSG { r["sm2_dec"] = "PASS" } else { r["sm2_dec"] = "FAIL" }
        }

        if ss, ok := ref["sm2_sig"].(string); ok && ss != "" {
                ok, _ := crossmool.Verify(MSG, DK["sig_pub_der"], ss)
                if ok { r["sm2_ver"] = "PASS" } else { r["sm2_ver"] = "FAIL" }
        }

        if sc, ok := ref["sm4_enc"].(string); ok && sc != "" {
                sk, _ := hex.DecodeString(SM4_KEY)
                sd, _ := crossmool.DecryptGcmToString(sk, sc)
                if sd == MSG { r["sm4_dec"] = "PASS" } else { r["sm4_dec"] = "FAIL" }
        }

        if sh, ok := ref["sm3_hash"].(string); ok && sh != "" {
                h := crossmool.DigestToStr(MSG, false)
                if h == sh { r["sm3"] = "PASS" } else { r["sm3"] = "FAIL" }
        }

        if hh, ok := ref["sm3_hmac_hash"].(string); ok && hh != "" {
                hm, _ := crossmool.HMACToStr("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", MSG, false)
                if hm == hh { r["sm3_hmac"] = "PASS" } else { r["sm3_hmac"] = "FAIL" }
        }

        o, _ := json.Marshal(r)
        fmt.Println(string(o))
}
