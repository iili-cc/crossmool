package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"cc.iili.tools/crossmool"
)

type JavaTestData struct {
	TestMessage string `json:"test_message"`
	SM2         struct {
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
	} `json:"sm2"`
	SM3 struct {
		DigestHex     string `json:"digest_hex"`
		DigestBase64  string `json:"digest_base64"`
		HmacKeyHex    string `json:"hmac_key_hex"`
		HmacKeyBase64 string `json:"hmac_key_base64"`
		HmacHex       string `json:"hmac_hex"`
		HmacBase64    string `json:"hmac_base64"`
	} `json:"sm3"`
	SM4 struct {
		KeyHex              string `json:"key_hex"`
		KeyBase64           string `json:"key_base64"`
		IvHex               string `json:"iv_hex"`
		GcmCiphertextHex    string `json:"gcm_ciphertext_hex"`
		GcmCiphertextBase64 string `json:"gcm_ciphertext_base64"`
		GcmCiphertextTagHex string `json:"gcm_ciphertext_tag_hex"`
	} `json:"sm4"`
}

func main() {
	inputPath := "testcase/java_go_test_data.json"
	if len(os.Args) > 1 {
		inputPath = os.Args[1]
	}

	fmt.Println("=== Go Verify Java-Generated SM Data ===")
	fmt.Printf("Reading test data from: %s\n\n", inputPath)

	// Read JSON file
	jsonBytes, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Printf("ERROR: read json: %v\n", err)
		os.Exit(1)
	}

	var data JavaTestData
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		fmt.Printf("ERROR: parse json: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Test Message: %s\n\n", data.TestMessage)

	allPassed := true

	// ========== SM2 Verification ==========
	fmt.Println("--- SM2 Verification ---")

	// Verify SM2 decrypt (Hex)
	pt, err := crossmool.Decrypt(data.SM2.CiphertextHex, data.SM2.PrivateKeyHex)
	if err != nil {
		fmt.Printf("FAIL: SM2 Decrypt (Hex): %v\n", err)
		allPassed = false
	} else if pt == data.TestMessage {
		fmt.Println("PASS: SM2 Decrypt (Hex)")
	} else {
		fmt.Printf("FAIL: SM2 Decrypt (Hex) - got: %s\n", pt)
		allPassed = false
	}

	// Verify SM2 decrypt (Base64)
	pt, err = crossmool.Decrypt(data.SM2.CiphertextBase64, data.SM2.PrivateKeyBase64)
	if err != nil {
		fmt.Printf("FAIL: SM2 Decrypt (Base64): %v\n", err)
		allPassed = false
	} else if pt == data.TestMessage {
		fmt.Println("PASS: SM2 Decrypt (Base64)")
	} else {
		fmt.Printf("FAIL: SM2 Decrypt (Base64) - got: %s\n", pt)
		allPassed = false
	}

	// Verify SM2 signature (Hex)
	ok, err := crossmool.Verify(data.TestMessage, data.SM2.PublicKeyHex, data.SM2.SignatureHex)
	if err != nil {
		fmt.Printf("FAIL: SM2 Verify (Hex): %v\n", err)
		allPassed = false
	} else if ok {
		fmt.Println("PASS: SM2 Verify (Hex)")
	} else {
		fmt.Println("FAIL: SM2 Verify (Hex) - signature invalid")
		allPassed = false
	}

	// Verify SM2 signature (Base64)
	ok, err = crossmool.Verify(data.TestMessage, data.SM2.PublicKeyBase64, data.SM2.SignatureBase64)
	if err != nil {
		fmt.Printf("FAIL: SM2 Verify (Base64): %v\n", err)
		allPassed = false
	} else if ok {
		fmt.Println("PASS: SM2 Verify (Base64)")
	} else {
		fmt.Println("FAIL: SM2 Verify (Base64) - signature invalid")
		allPassed = false
	}

	// Verify SM2 EncryptSign (Hex)
	pt, err = crossmool.VerifyDecrypt(data.SM2.EncryptSign.Hex.Ciphertext, data.SM2.EncryptSign.Hex.Signature, data.SM2.PublicKeyHex, data.SM2.PrivateKeyHex)
	if err != nil {
		fmt.Printf("FAIL: SM2 VerifyDecrypt (Hex): %v\n", err)
		allPassed = false
	} else if pt == data.TestMessage {
		fmt.Println("PASS: SM2 VerifyDecrypt (Hex)")
	} else {
		fmt.Printf("FAIL: SM2 VerifyDecrypt (Hex) - got: %s\n", pt)
		allPassed = false
	}

	// Verify SM2 EncryptSign (Base64)
	pt, err = crossmool.VerifyDecrypt(data.SM2.EncryptSign.Base64.Ciphertext, data.SM2.EncryptSign.Base64.Signature, data.SM2.PublicKeyBase64, data.SM2.PrivateKeyBase64)
	if err != nil {
		fmt.Printf("FAIL: SM2 VerifyDecrypt (Base64): %v\n", err)
		allPassed = false
	} else if pt == data.TestMessage {
		fmt.Println("PASS: SM2 VerifyDecrypt (Base64)")
	} else {
		fmt.Printf("FAIL: SM2 VerifyDecrypt (Base64) - got: %s\n", pt)
		allPassed = false
	}

	// ========== SM3 Verification ==========
	fmt.Println("\n--- SM3 Verification ---")

	// Verify SM3 digest (Hex)
	digestHex := crossmool.DigestHex([]byte(data.TestMessage))
	if digestHex == data.SM3.DigestHex {
		fmt.Println("PASS: SM3 Digest (Hex)")
	} else {
		fmt.Printf("FAIL: SM3 Digest (Hex) - expected: %s, got: %s\n", data.SM3.DigestHex, digestHex)
		allPassed = false
	}

	// Verify SM3 digest (Base64)
	digestBase64 := crossmool.DigestBase64([]byte(data.TestMessage))
	if digestBase64 == data.SM3.DigestBase64 {
		fmt.Println("PASS: SM3 Digest (Base64)")
	} else {
		fmt.Printf("FAIL: SM3 Digest (Base64) - expected: %s, got: %s\n", data.SM3.DigestBase64, digestBase64)
		allPassed = false
	}

	// Verify HMAC-SM3 (Hex)
	hmacHex, err := crossmool.HMACToStr(data.SM3.HmacKeyHex, data.TestMessage, false)
	if err != nil {
		fmt.Printf("FAIL: HMAC-SM3 (Hex): %v\n", err)
		allPassed = false
	} else if hmacHex == data.SM3.HmacHex {
		fmt.Println("PASS: HMAC-SM3 (Hex)")
	} else {
		fmt.Printf("FAIL: HMAC-SM3 (Hex) - expected: %s, got: %s\n", data.SM3.HmacHex, hmacHex)
		allPassed = false
	}

	// Verify HMAC-SM3 (Base64)
	hmacBase64, err := crossmool.HMACToStr(data.SM3.HmacKeyBase64, data.TestMessage, true)
	if err != nil {
		fmt.Printf("FAIL: HMAC-SM3 (Base64): %v\n", err)
		allPassed = false
	} else if hmacBase64 == data.SM3.HmacBase64 {
		fmt.Println("PASS: HMAC-SM3 (Base64)")
	} else {
		fmt.Printf("FAIL: HMAC-SM3 (Base64) - expected: %s, got: %s\n", data.SM3.HmacBase64, hmacBase64)
		allPassed = false
	}

	// ========== SM4-GCM Verification ==========
	fmt.Println("\n--- SM4-GCM Verification ---")

	// Decode SM4 key
	sm4Key, err := hex.DecodeString(data.SM4.KeyHex)
	if err != nil {
		fmt.Printf("FAIL: decode SM4 key: %v\n", err)
		allPassed = false
	} else {
		// Verify SM4-GCM decrypt
		decrypted, err := crossmool.DecryptGcm(sm4Key, data.SM4.GcmCiphertextHex)
		if err != nil {
			fmt.Printf("FAIL: SM4-GCM Decrypt: %v\n", err)
			allPassed = false
		} else if string(decrypted) == data.TestMessage {
			fmt.Println("PASS: SM4-GCM Decrypt")
		} else {
			fmt.Printf("FAIL: SM4-GCM Decrypt - got: %s\n", string(decrypted))
			allPassed = false
		}
	}

	// ========== Summary ==========
	fmt.Println("\n=== Verification Summary ===")
	if allPassed {
		fmt.Println("ALL TESTS PASSED!")
	} else {
		fmt.Println("SOME TESTS FAILED!")
		os.Exit(1)
	}
}