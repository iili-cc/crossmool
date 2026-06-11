package main

import (
	crossmool "cc.iili.tools/crossmool"
	"encoding/json"
	"fmt"
)

func main() {
	MSG := "Hello, 这是跨语言国密互通性测试数据"
	dk := map[string]string{
		"enc_pub_der":  "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
		"enc_priv_der": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
		"sig_pub_der":  "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
		"sig_priv_der": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
	}
	HMAC_KEY := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	SM4_KEY := "0123456789abcdeffedcba9876543210"

	r := map[string]interface{}{}

	// SM2 Enc/Dec
	c, err := crossmool.Encrypt(MSG, dk["enc_pub_der"], false)
	if err != nil {
		r["sm2_enc_dec"] = "FAIL: " + err.Error()
	} else {
		r["sm2_enc"] = c
		d, err := crossmool.Decrypt(c, dk["enc_priv_der"])
		if err != nil {
			r["sm2_enc_dec"] = "FAIL: " + err.Error()
		} else {
			r["sm2_enc_dec"] = map[bool]string{true: "PASS", false: "FAIL"}[d == MSG]
		}
	}

	// SM2 Sig/Ver
	s, err := crossmool.Sign(MSG, dk["sig_priv_der"], false)
	if err != nil {
		r["sm2_sig_ver"] = "FAIL: " + err.Error()
	} else {
		r["sm2_sig"] = s
		ok, _ := crossmool.Verify(MSG, dk["sig_pub_der"], s)
		r["sm2_sig_ver"] = map[bool]string{true: "PASS", false: "FAIL"}[ok]
	}

	// SM3
	r["sm3_hash"] = crossmool.DigestToStr(MSG, false)

	// SM3-HMAC
	h, _ := crossmool.HMACToStr(HMAC_KEY, MSG, false)
	r["sm3_hmac_hash"] = h

	// SM4
	sk, _ := crossmool.DecodeHexString(SM4_KEY)
	sc, _ := crossmool.EncryptGcm(sk, []byte(MSG), false)
	r["sm4_enc"] = sc
	sd, _ := crossmool.DecryptGcmToString(sk, sc)
	r["sm4_enc_dec"] = map[bool]string{true: "PASS", false: "FAIL"}[sd == MSG]

	// Cross data
	r["cross"] = map[string]interface{}{
		"sm2_enc":       r["sm2_enc"],
		"sm2_sig":       r["sm2_sig"],
		"sm4_enc":       r["sm4_enc"],
		"sm3_hash":      r["sm3_hash"],
		"sm3_hmac_hash": r["sm3_hmac_hash"],
	}

	o, _ := json.Marshal(r)
	fmt.Println(string(o))
}
