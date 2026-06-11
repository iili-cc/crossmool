package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	crossmool "D:/workspaces/git/corssmool/crossmool/golang/crossmool"
)

func main() {
	msg := "Hello, 这是跨语言国密互通性测试数据"
	encPubKey := "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
	encPrivKey := "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03"
	signPrivKey := "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3"
	signPubKey := "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"
	sm4KeyHex := "0123456789abcdeffedcba9876543210"
	hmacKeyHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	result := make(map[string]interface{})

	// SM2 Encrypt
	cipherHex, err := crossmool.Encrypt(msg, encPubKey, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SM2 encrypt error: %v\n", err)
	} else {
		cipherB64, _ := crossmool.Encrypt(msg, encPubKey, true)
		result["sm2_encrypt"] = map[string]string{"cipher_hex": cipherHex, "cipher_b64": cipherB64}
	}

	// SM2 Sign
	sigHex, err := crossmool.Sign(msg, signPrivKey, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SM2 sign error: %v\n", err)
	} else {
		sigB64, _ := crossmool.Sign(msg, signPrivKey, true)
		result["sm2_sign"] = map[string]string{"signature_hex": sigHex, "signature_b64": sigB64}
	}

	// SM2 EncryptSign
	if cipherHex != "" {
		sigOnCipher, _ := crossmool.Sign(cipherHex, signPrivKey, false)
		result["sm2_encrypt_sign"] = map[string]string{"cipher_hex": cipherHex, "signature_hex": sigOnCipher}
	}

	// SM3
	digestHex := crossmool.DigestToStr(msg, false)
	digestB64 := crossmool.DigestToStr(msg, true)
	result["sm3"] = map[string]string{"digest_hex": digestHex, "digest_b64": digestB64}

	// SM3-HMAC
	hmacHex, _ := crossmool.HMACToStr(hmacKeyHex, msg, false)
	hmacB64, _ := crossmool.HMACToStr(hmacKeyHex, msg, true)
	result["sm3_hmac"] = map[string]string{"hmac_hex": hmacHex, "hmac_b64": hmacB64}

	// SM4 GCM
	sm4Key, _ := hex.DecodeString(sm4KeyHex)
	sm4Hex, _ := crossmool.EncryptGcm(sm4Key, []byte(msg), false)
	sm4B64, _ := crossmool.EncryptGcm(sm4Key, []byte(msg), true)
	result["sm4"] = map[string]interface{}{"cipher_hex": sm4Hex, "cipher_b64": sm4B64, "key_hex": sm4KeyHex}

	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
	_ = encPrivKey
	_ = signPubKey
}
