package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"cc.iili.tools/crossmool"
)

type TestMessage struct {
	Message string `json:"test_message"`
}

type SM2Data struct {
	PublicKeyHex     string `json:"public_key_hex"`
	PrivateKeyHex    string `json:"private_key_hex"`
	PublicKeyBase64  string `json:"public_key_base64"`
	PrivateKeyBase64 string `json:"private_key_base64"`
	CiphertextHex    string `json:"ciphertext_hex"`
	CiphertextBase64 string `json:"ciphertext_base64"`
	SignatureHex     string `json:"signature_hex"`
	SignatureBase64  string `json:"signature_base64"`
	EncryptSign      struct {
		Hex struct {
			Ciphertext string `json:"ciphertext"`
			Signature  string `json:"signature"`
		} `json:"hex"`
		Base64 struct {
			Ciphertext string `json:"ciphertext"`
			Signature  string `json:"signature"`
		} `json:"base64"`
	} `json:"encrypt_sign"`
}

type SM3Data struct {
	DigestHex     string `json:"digest_hex"`
	DigestBase64  string `json:"digest_base64"`
	HmacKeyHex    string `json:"hmac_key_hex"`
	HmacKeyBase64 string `json:"hmac_key_base64"`
	HmacHex       string `json:"hmac_hex"`
	HmacBase64    string `json:"hmac_base64"`
}

type SM4Data struct {
	KeyHex              string `json:"key_hex"`
	KeyBase64           string `json:"key_base64"`
	IvHex               string `json:"iv_hex"`
	GcmCiphertextHex    string `json:"gcm_ciphertext_hex"`
	GcmCiphertextBase64 string `json:"gcm_ciphertext_base64"`
	GcmCipherTagHex     string `json:"gcm_cipher_tag_hex"`
}

type TestData struct {
	TestMessage string  `json:"test_message"`
	SM2         SM2Data `json:"sm2"`
	SM3         SM3Data `json:"sm3"`
	SM4         SM4Data `json:"sm4"`
}

var (
	passCount int
	failCount int
)

func report(name string, pass bool, detail string) {
	status := "PASS"
	if !pass {
		status = "FAIL"
		failCount++
	} else {
		passCount++
	}
	if detail != "" {
		fmt.Printf("[%s] %s - %s\n", status, name, detail)
	} else {
		fmt.Printf("[%s] %s\n", status, name)
	}
}

func main() {
	jsonPath := "../java_go_test_data.json"
	if len(os.Args) > 1 {
		jsonPath = os.Args[1]
	}

	absPath, err := filepath.Abs(jsonPath)
	if err != nil {
		fmt.Printf("ERROR: resolve json path: %v\n", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(absPath)
	if err != nil {
		fmt.Printf("ERROR: read json file: %v\n", err)
		os.Exit(1)
	}

	var td TestData
	if err := json.Unmarshal(data, &td); err != nil {
		fmt.Printf("ERROR: parse json: %v\n", err)
		os.Exit(1)
	}

	msg := td.TestMessage
	fmt.Println("========================================")
	fmt.Println("  Java-Go Interoperability Test")
	fmt.Println("========================================")
	fmt.Printf("Test Message: %s\n\n", msg)

	testSM2(msg, td.SM2)
	testSM3(msg, td.SM3)
	testSM4(td.SM4)

	fmt.Println("========================================")
	fmt.Printf("Total: %d PASS, %d FAIL\n", passCount, failCount)
	if failCount > 0 {
		fmt.Println("RESULT: FAILED")
		os.Exit(1)
	}
	fmt.Println("RESULT: ALL PASSED")
}

func testSM2(msg string, d SM2Data) {
	fmt.Println("--- SM2 Tests ---")

	// 1. Decrypt Hex ciphertext with Hex private key
	pt, err := crossmool.Decrypt(d.CiphertextHex, d.PrivateKeyHex)
	if err != nil {
		report("SM2 Decrypt Hex", false, err.Error())
	} else {
		report("SM2 Decrypt Hex", pt == msg, fmt.Sprintf("got=%q", pt))
	}

	// 2. Decrypt Base64 ciphertext with Base64 private key
	pt, err = crossmool.Decrypt(d.CiphertextBase64, d.PrivateKeyBase64)
	if err != nil {
		report("SM2 Decrypt Base64", false, err.Error())
	} else {
		report("SM2 Decrypt Base64", pt == msg, fmt.Sprintf("got=%q", pt))
	}

	// 3. Verify Hex signature with Hex public key
	ok, err := crossmool.Verify(msg, d.PublicKeyHex, d.SignatureHex)
	if err != nil {
		report("SM2 Verify Hex", false, err.Error())
	} else {
		report("SM2 Verify Hex", ok, "")
	}

	// 4. Verify Base64 signature with Base64 public key
	ok, err = crossmool.Verify(msg, d.PublicKeyBase64, d.SignatureBase64)
	if err != nil {
		report("SM2 Verify Base64", false, err.Error())
	} else {
		report("SM2 Verify Base64", ok, "")
	}

	// 5. VerifyDecrypt Hex encrypt_sign pair
	pt, err = crossmool.VerifyDecrypt(
		d.EncryptSign.Hex.Ciphertext,
		d.EncryptSign.Hex.Signature,
		d.PublicKeyHex,
		d.PrivateKeyHex,
	)
	if err != nil {
		report("SM2 VerifyDecrypt Hex", false, err.Error())
	} else {
		report("SM2 VerifyDecrypt Hex", pt == msg, fmt.Sprintf("got=%q", pt))
	}

	// 6. VerifyDecrypt Base64 encrypt_sign pair
	pt, err = crossmool.VerifyDecrypt(
		d.EncryptSign.Base64.Ciphertext,
		d.EncryptSign.Base64.Signature,
		d.PublicKeyBase64,
		d.PrivateKeyBase64,
	)
	if err != nil {
		report("SM2 VerifyDecrypt Base64", false, err.Error())
	} else {
		report("SM2 VerifyDecrypt Base64", pt == msg, fmt.Sprintf("got=%q", pt))
	}

	fmt.Println()
}

func testSM3(msg string, d SM3Data) {
	fmt.Println("--- SM3 Tests ---")

	// 1. Compute digest and compare with Hex
	goDigestHex := crossmool.DigestHex([]byte(msg))
	report("SM3 Digest Hex", goDigestHex == d.DigestHex,
		fmt.Sprintf("go=%s java=%s", goDigestHex, d.DigestHex))

	// 2. Compute digest and compare with Base64
	goDigestBase64 := crossmool.DigestBase64([]byte(msg))
	report("SM3 Digest Base64", goDigestBase64 == d.DigestBase64,
		fmt.Sprintf("go=%s java=%s", goDigestBase64, d.DigestBase64))

	// 3. HMAC-SM3 with Hex key
	hmacHex, err := crossmool.HMACToStr(d.HmacKeyHex, msg, false)
	if err != nil {
		report("HMAC-SM3 Hex key", false, err.Error())
	} else {
		report("HMAC-SM3 Hex key", hmacHex == d.HmacHex,
			fmt.Sprintf("go=%s java=%s", hmacHex, d.HmacHex))
	}

	// 4. HMAC-SM3 with Base64 key
	hmacBase64, err := crossmool.HMACToStr(d.HmacKeyBase64, msg, true)
	if err != nil {
		report("HMAC-SM3 Base64 key", false, err.Error())
	} else {
		report("HMAC-SM3 Base64 key", hmacBase64 == d.HmacBase64,
			fmt.Sprintf("go=%s java=%s", hmacBase64, d.HmacBase64))
	}

	fmt.Println()
}

func testSM4(d SM4Data) {
	fmt.Println("--- SM4-GCM Tests ---")

	// 1. Decrypt Hex GCM ciphertext with Hex key
	keyBytes, err := crossmool.DecodeHexString(d.KeyHex)
	if err != nil {
		report("SM4-GCM Decrypt Hex", false, "decode key: "+err.Error())
	} else {
		pt, err := crossmool.DecryptGcm(keyBytes, d.GcmCiphertextHex)
		if err != nil {
			report("SM4-GCM Decrypt Hex", false, err.Error())
		} else {
			report("SM4-GCM Decrypt Hex", true, fmt.Sprintf("got=%q", string(pt)))
		}
	}

	// 2. Decrypt Base64 GCM ciphertext with Base64 key
	keyB64Bytes, err := crossmool.DecodeBase64String(d.KeyBase64)
	if err != nil {
		report("SM4-GCM Decrypt Base64", false, "decode key: "+err.Error())
	} else {
		pt, err := crossmool.DecryptGcm(keyB64Bytes, d.GcmCiphertextBase64)
		if err != nil {
			report("SM4-GCM Decrypt Base64", false, err.Error())
		} else {
			report("SM4-GCM Decrypt Base64", true, fmt.Sprintf("got=%q", string(pt)))
		}
	}

	fmt.Println()
}