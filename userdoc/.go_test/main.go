package main

import (
	"encoding/json"
	"fmt"
	"os"

	crossmool "cc.iili.tools/crossmool"
)

type TV struct {
	EncPubPem   string `json:"enc_pub_pem"`
	EncPrivPem  string `json:"enc_priv_pem"`
	SigPubPem   string `json:"sig_pub_pem"`
	SigPrivPem  string `json:"sig_priv_pem"`
	EncPubHex   string `json:"enc_pub_hex"`
	EncPrivHex  string `json:"enc_priv_hex"`
	SigPubHex   string `json:"sig_pub_hex"`
	SigPrivHex  string `json:"sig_priv_hex"`
	Plain1      string `json:"plain1"`
	Plain2      string `json:"plain2"`
}

func main() {
	data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	var tv TV
	json.Unmarshal(data, &tv)

	// Use PEM keys for Go
	encPubDer, _ := crossmool.ImportPublicKeyPEM([]byte(tv.EncPubPem))
	encPrivDer, _ := crossmool.ImportPrivateKeyPEM([]byte(tv.EncPrivPem))
	sigPubDer, _ := crossmool.ImportPublicKeyPEM([]byte(tv.SigPubPem))
	sigPrivDer, _ := crossmool.ImportPrivateKeyPEM([]byte(tv.SigPrivPem))
	encPub := crossmool.EncodeHex(encPubDer)
	encPriv := crossmool.EncodeHex(encPrivDer)
	sigPub := crossmool.EncodeHex(sigPubDer)
	sigPriv := crossmool.EncodeHex(sigPrivDer)

	fail := 0
	check := func(name string, ok bool, e error) {
		s := "PASS"
		if !ok { s = "FAIL"; fail++ }
		if e != nil { s += fmt.Sprintf("(err:%v)", e) }
		fmt.Printf("  %-30s %s\n", name, s)
	}

	// Self encrypt/decrypt
	ct1, e := crossmool.EncryptDefault(tv.Plain1, encPub)
	check("encrypt_hex", ct1 != "" && e == nil, e)
	pt1, e := crossmool.Decrypt(ct1, encPriv)
	check("decrypt_hex_self", pt1 == tv.Plain1 && e == nil, e)

	ct1b, e := crossmool.Encrypt(tv.Plain1, encPub, true)
	check("encrypt_b64", ct1b != "" && e == nil, e)
	pt1b, e := crossmool.Decrypt(ct1b, encPriv)
	check("decrypt_b64_self", pt1b == tv.Plain1 && e == nil, e)

	// Cross decrypt (Python-generated)
	ptP, e := crossmool.Decrypt(readField("ct1_hex"), encPriv)
	check("decrypt_hex_py", ptP == tv.Plain1 && e == nil, e)
	ptPb, e := crossmool.Decrypt(readField("ct1_b64"), encPriv)
	check("decrypt_b64_py", ptPb == tv.Plain1 && e == nil, e)

	// Self encrypt_sign
	esp, e := crossmool.EncryptSignDefault(tv.Plain2, encPub, sigPriv)
	check("encrypt_sign_hex", esp != nil && e == nil, e)
	vd1, e := crossmool.VerifyDecrypt(esp.Ciphertext, esp.Signature, sigPub, encPriv)
	check("verify_decrypt_hex_self", vd1 == tv.Plain2 && e == nil, e)

	// Cross verify_decrypt (Python)
	vd2, e := crossmool.VerifyDecrypt(readField("ct2_hex"), readField("sig2_hex"), sigPub, encPriv)
	check("verify_decrypt_hex_py", vd2 == tv.Plain2 && e == nil, e)
	vd3, e := crossmool.VerifyDecrypt(readField("ct2_b64"), readField("sig2_b64"), sigPub, encPriv)
	check("verify_decrypt_b64_py", vd3 == tv.Plain2 && e == nil, e)

	fmt.Printf("\n  %d/%d passed\n", 12-fail, 12)
	if fail > 0 { os.Exit(1) }
}

func readField(k string) string {
	data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
	var m map[string]string
	json.Unmarshal(data, &m)
	return m[k]
}
