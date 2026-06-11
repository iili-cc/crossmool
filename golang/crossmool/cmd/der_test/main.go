package main

import (
	crossmool "cc.iili.tools/crossmool"
	"encoding/json"
	"fmt"
)

func main() {
	derPub := "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
	derPriv := "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
	derSigPub := "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"
	derSigPriv := "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"

	msg := "Hello, 这是跨语言国密互通性测试数据"
	hmacKey := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	sm4KeyHex := "0123456789abcdeffedcba9876543210"
	EXP_SM3 := "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
	EXP_HMAC := "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"

	r := make(map[string]interface{})

	// SM3
	d := crossmool.DigestToStr(msg, false)
	r["sm3"] = d
	r["sm3_ok"] = d == EXP_SM3

	// SM3-HMAC
	h, _ := crossmool.HMACToStr(hmacKey, msg, false)
	r["sm3_hmac"] = h
	r["sm3_hmac_ok"] = h == EXP_HMAC

	// SM2 Encrypt
	cipher, err := crossmool.Encrypt(msg, derPub, false)
	if err != nil {
		r["sm2_enc_err"] = err.Error()
	} else {
		r["sm2_enc"] = cipher
		// SM2 Decrypt (self-test)
		dec, err := crossmool.Decrypt(cipher, derPriv)
		if err != nil {
			r["sm2_dec_err"] = err.Error()
		} else {
			r["sm2_dec_ok"] = dec == msg
		}
	}

	// SM2 Sign
	sig, err := crossmool.Sign(msg, derSigPriv, false)
	if err != nil {
		r["sm2_sig_err"] = err.Error()
	} else {
		r["sm2_sig"] = sig
		ok, _ := crossmool.Verify(msg, derSigPub, sig)
		r["sm2_ver_ok"] = ok
	}

	// SM4 GCM
	sm4Key, _ := crossmool.DecodeHexString(sm4KeyHex)
	sm4Enc, _ := crossmool.EncryptGcm(sm4Key, []byte(msg), false)
	r["sm4_enc"] = sm4Enc
	sm4Dec, _ := crossmool.DecryptGcmToString(sm4Key, sm4Enc)
	r["sm4_dec_ok"] = sm4Dec == msg

	o, _ := json.Marshal(r)
	fmt.Println(string(o))
}
