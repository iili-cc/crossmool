package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"cc.iili.tools/crossmool"
)

type GoEncryptSignData struct {
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
	outputPath := "testcase/go_java_test_data.json"
	if len(os.Args) > 1 {
		outputPath = os.Args[1]
	}

	testMessage := "Hello, Go-Java Interop Test!"
	fmt.Println("=== Go SM Interop Test Data Generator ===")
	fmt.Printf("Test Message: %s\n\n", testMessage)

	var data GoEncryptSignData
	data.TestMessage = testMessage

	fixedIv := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}

	// ========== SM2 ==========
	fmt.Println("--- SM2 ---")

	pubHex, privHex, err := crossmool.GenerateKeyPairHex()
	if err != nil {
		fmt.Printf("ERROR: generate SM2 keypair hex: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SM2 PublicKey (Hex):  %s\n", pubHex)
	fmt.Printf("SM2 PrivateKey (Hex): %s\n", privHex)

	pubBase64, privBase64, err := crossmool.GenerateKeyPairBase64()
	if err != nil {
		fmt.Printf("ERROR: generate SM2 keypair base64: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SM2 PublicKey (Base64):  %s\n", pubBase64)
	fmt.Printf("SM2 PrivateKey (Base64): %s\n", privBase64)

	data.SM2.PublicKeyHex = pubHex
	data.SM2.PrivateKeyHex = privHex
	data.SM2.PublicKeyBase64 = pubBase64
	data.SM2.PrivateKeyBase64 = privBase64

	ciphertextHex, err := crossmool.Encrypt(testMessage, pubHex, false)
	if err != nil {
		fmt.Printf("ERROR: SM2 encrypt hex: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SM2 Ciphertext (Hex): %s\n", ciphertextHex)
	data.SM2.CiphertextHex = ciphertextHex

	ciphertextBase64, err := crossmool.Encrypt(testMessage, pubBase64, true)
	if err != nil {
		fmt.Printf("ERROR: SM2 encrypt base64: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SM2 Ciphertext (Base64): %s\n", ciphertextBase64)
	data.SM2.CiphertextBase64 = ciphertextBase64

	pt, _ := crossmool.Decrypt(ciphertextHex, privHex)
	fmt.Printf("SM2 Decrypt verify (Hex): %v\n", pt == testMessage)
	pt, _ = crossmool.Decrypt(ciphertextBase64, privBase64)
	fmt.Printf("SM2 Decrypt verify (Base64): %v\n", pt == testMessage)

	signatureHex, err := crossmool.Sign(testMessage, privHex, false)
	if err != nil {
		fmt.Printf("ERROR: SM2 sign hex: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SM2 Signature (Hex): %s\n", signatureHex)
	data.SM2.SignatureHex = signatureHex

	signatureBase64, err := crossmool.Sign(testMessage, privBase64, true)
	if err != nil {
		fmt.Printf("ERROR: SM2 sign base64: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SM2 Signature (Base64): %s\n", signatureBase64)
	data.SM2.SignatureBase64 = signatureBase64

	ok, _ := crossmool.Verify(testMessage, pubHex, signatureHex)
	fmt.Printf("SM2 Verify (Hex): %v\n", ok)
	ok, _ = crossmool.Verify(testMessage, pubBase64, signatureBase64)
	fmt.Printf("SM2 Verify (Base64): %v\n", ok)

	encSignHex, err := crossmool.EncryptSign(testMessage, pubHex, privHex, false)
	if err != nil {
		fmt.Printf("ERROR: SM2 encryptSign hex: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SM2 EncryptSign Ciphertext (Hex): %s\n", encSignHex.Ciphertext)
	fmt.Printf("SM2 EncryptSign Signature (Hex): %s\n", encSignHex.Signature)
	data.SM2.EncryptSign.Hex.Ciphertext = encSignHex.Ciphertext
	data.SM2.EncryptSign.Hex.Signature = encSignHex.Signature

	encSignBase64, err := crossmool.EncryptSign(testMessage, pubBase64, privBase64, true)
	if err != nil {
		fmt.Printf("ERROR: SM2 encryptSign base64: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SM2 EncryptSign Ciphertext (Base64): %s\n", encSignBase64.Ciphertext)
	fmt.Printf("SM2 EncryptSign Signature (Base64): %s\n", encSignBase64.Signature)
	data.SM2.EncryptSign.Base64.Ciphertext = encSignBase64.Ciphertext
	data.SM2.EncryptSign.Base64.Signature = encSignBase64.Signature

	pt, err = crossmool.VerifyDecrypt(encSignHex.Ciphertext, encSignHex.Signature, pubHex, privHex)
	if err == nil {
		fmt.Printf("SM2 VerifyDecrypt (Hex): %v\n", pt == testMessage)
	}
	pt, err = crossmool.VerifyDecrypt(encSignBase64.Ciphertext, encSignBase64.Signature, pubBase64, privBase64)
	if err == nil {
		fmt.Printf("SM2 VerifyDecrypt (Base64): %v\n", pt == testMessage)
	}

	// ========== SM3 ==========
	fmt.Println("\n--- SM3 ---")

	digestHex := crossmool.DigestHex([]byte(testMessage))
	fmt.Printf("SM3 Digest (Hex): %s\n", digestHex)
	data.SM3.DigestHex = digestHex

	digestBase64 := crossmool.DigestBase64([]byte(testMessage))
	fmt.Printf("SM3 Digest (Base64): %s\n", digestBase64)
	data.SM3.DigestBase64 = digestBase64

	hmacKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hmacKeyBytes, _ := hex.DecodeString(hmacKeyHex)
	hmacKeyBase64 := base64.StdEncoding.EncodeToString(hmacKeyBytes)
	data.SM3.HmacKeyHex = hmacKeyHex
	data.SM3.HmacKeyBase64 = hmacKeyBase64

	hmacHex, err := crossmool.HMACToStr(hmacKeyHex, testMessage, false)
	if err != nil {
		fmt.Printf("ERROR: HMAC-SM3 hex: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("HMAC-SM3 (Hex): %s\n", hmacHex)
	data.SM3.HmacHex = hmacHex

	hmacBase64, err := crossmool.HMACToStr(hmacKeyBase64, testMessage, true)
	if err != nil {
		fmt.Printf("ERROR: HMAC-SM3 base64: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("HMAC-SM3 (Base64): %s\n", hmacBase64)
	data.SM3.HmacBase64 = hmacBase64

	// ========== SM4-GCM ==========
	fmt.Println("\n--- SM4-GCM ---")

	sm4Key, _ := crossmool.GenerateKey()
	sm4KeyHex := hex.EncodeToString(sm4Key)
	sm4KeyBase64 := base64.StdEncoding.EncodeToString(sm4Key)
	fmt.Printf("SM4 Key (Hex): %s\n", sm4KeyHex)
	fmt.Printf("SM4 Key (Base64): %s\n", sm4KeyBase64)
	data.SM4.KeyHex = sm4KeyHex
	data.SM4.KeyBase64 = sm4KeyBase64

	ivHex := hex.EncodeToString(fixedIv)
	fmt.Printf("SM4 IV (Hex): %s\n", ivHex)
	data.SM4.IvHex = ivHex

	encrypted, err := crossmool.EncryptGcmWithIV(sm4Key, []byte(testMessage), fixedIv, false)
	if err != nil {
		fmt.Printf("ERROR: SM4-GCM encrypt: %v\n", err)
		os.Exit(1)
	}
	encryptedHex := encrypted
	encryptedBase64, _ := crossmool.EncryptGcmWithIV(sm4Key, []byte(testMessage), fixedIv, true)
	fmt.Printf("SM4-GCM Ciphertext (Hex): %s\n", encryptedHex)
	fmt.Printf("SM4-GCM Ciphertext (Base64): %s\n", encryptedBase64)
	data.SM4.GcmCiphertextHex = encryptedHex
	data.SM4.GcmCiphertextBase64 = encryptedBase64

	encryptedBytes, _ := hex.DecodeString(encryptedHex)
	cipherWithTag := encryptedBytes[12:]
	cipherWithTagHex := hex.EncodeToString(cipherWithTag)
	fmt.Printf("SM4-GCM Ciphertext+Tag (Hex): %s\n", cipherWithTagHex)
	data.SM4.GcmCiphertextTagHex = cipherWithTagHex

	decrypted, err := crossmool.DecryptGcm(sm4Key, encryptedHex)
	if err == nil {
		fmt.Printf("SM4-GCM Decrypt verify: %v\n", string(decrypted) == testMessage)
	}

	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	if err := os.WriteFile(outputPath, jsonBytes, 0644); err != nil {
		fmt.Printf("ERROR: write json: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nTest data saved to: %s\n", outputPath)
	fmt.Println("\n=== Go test data generation complete! ===")
}