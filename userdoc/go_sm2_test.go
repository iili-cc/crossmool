package main

import (
	"encoding/json"
	"fmt"
	"os"

	crossmool "github.com/corssmool/crossmool/golang/crossmool"
)

type TV struct {
	EncPubHex  string `json:"enc_pub_hex"`
	EncPrivHex string `json:"enc_priv_hex"`
	SigPubHex  string `json:"sig_pub_hex"`
	SigPrivHex string `json:"sig_priv_hex"`
	Plain1     string `json:"plain1"`
	Plain2     string `json:"plain2"`
}

func main() {
	data, err := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR reading test_vectors.json: %v\n", err)
		os.Exit(1)
	}
	var tv TV
	if err := json.Unmarshal(data, &tv); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR parsing json: %v\n", err)
		os.Exit(1)
	}

	fail := 0
	check := func(name string, ok bool) {
		if ok {
			fmt.Printf("  %-25s PASS\n", name)
		} else {
			fmt.Printf("  %-25s FAIL\n", name)
			fail++
		}
	}

	// Self encrypt/decrypt
	ctHex, err := crossmool.EncryptDefault(tv.Plain1, tv.EncPubHex)
	check("encrypt_hex_self", err == nil && len(ctHex) > 0)
	ctB64, err := crossmool.Encrypt(tv.Plain1, tv.EncPubHex, true)
	check("encrypt_b64_self", err == nil && len(ctB64) > 0)

	// Self decrypt
	pt1, err := crossmool.Decrypt(ctHex, tv.EncPrivHex)
	check("decrypt_hex_self", err == nil && pt1 == tv.Plain1)
	pt1b, err := crossmool.Decrypt(ctB64, tv.EncPrivHex)
	check("decrypt_b64_self", err == nil && pt1b == tv.Plain1)

	// Cross decrypt: Python-generated ciphertexts
	pd1, err := crossmool.Decrypt(readHex(), tv.EncPrivHex)
	check("decrypt_hex_py", err == nil && pd1 == tv.Plain1)
	pd2, err := crossmool.Decrypt(readB64(), tv.EncPrivHex)
	check("decrypt_b64_py", err == nil && pd2 == tv.Plain1)

	// Self encrypt_sign
	esp, err := crossmool.EncryptSignDefault(tv.Plain2, tv.EncPubHex, tv.SigPrivHex)
	check("encrypt_sign_hex_self", err == nil && esp != nil && len(esp.Ciphertext) > 0 && len(esp.Signature) > 0)
	espb, err := crossmool.EncryptSign(tv.Plain2, tv.EncPubHex, tv.SigPrivHex, true)
	check("encrypt_sign_b64_self", err == nil && espb != nil)

	// Self verify_decrypt
	vd, err := crossmool.VerifyDecrypt(esp.Ciphertext, esp.Signature, tv.SigPubHex, tv.EncPrivHex)
	check("verify_decrypt_hex_self", err == nil && vd == tv.Plain2)

	// Cross verify_decrypt: Python-generated
	crossVD, err := crossmool.VerifyDecrypt(readHex2(), readSigHex(), tv.SigPubHex, tv.EncPrivHex)
	check("verify_decrypt_hex_py", err == nil && crossVD == tv.Plain2)
	crossVDb, err := crossmool.VerifyDecrypt(readB642(), readSigB64(), tv.SigPubHex, tv.EncPrivHex)
	check("verify_decrypt_b64_py", err == nil && crossVDb == tv.Plain2)

	if fail > 0 {
		fmt.Printf("\n  %d TESTS FAILED\n", fail)
		os.Exit(1)
	} else {
		fmt.Println("\n  ALL OK")
	}
}

// Read from the test vectors file directly since embedding hex strings is impractical
func readHex() string {
	data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	var m map[string]string
	json.Unmarshal(data, &m)
	return m["ct1_hex"]
}
func readB64() string {
	data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	var m map[string]string
	json.Unmarshal(data, &m)
	return m["ct1_b64"]
}
func readHex2() string {
	data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	var m map[string]string
	json.Unmarshal(data, &m)
	return m["ct2_hex"]
}
func readSigHex() string {
	data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	var m map[string]string
	json.Unmarshal(data, &m)
	return m["sig2_hex"]
}
func readB642() string {
	data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	var m map[string]string
	json.Unmarshal(data, &m)
	return m["ct2_b64"]
}
func readSigB64() string {
	data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	var m map[string]string
	json.Unmarshal(data, &m)
	return m["sig2_b64"]
}
