package crossmool

import (
	"bytes"
	"testing"
)

func TestSM2_EncryptDecrypt_SignVerify(t *testing.T) {
	pubDER, privDER, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	msg := []byte("hello sm2")

	// Encrypt / Decrypt
	ct, err := EncryptBytes(msg, pubDER)
	if err != nil {
		t.Fatalf("EncryptBytes failed: %v", err)
	}

	pt, err := DecryptBytes(ct, privDER)
	if err != nil {
		t.Fatalf("DecryptBytes failed: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("decrypted plaintext mismatch: got %x want %x", pt, msg)
	}

	// Sign / Verify
	sig, err := SignBytes(msg, privDER)
	if err != nil {
		t.Fatalf("SignBytes failed: %v", err)
	}
	ok, err := VerifyBytes(msg, sig, pubDER)
	if err != nil {
		t.Fatalf("VerifyBytes failed: %v", err)
	}
	if !ok {
		t.Fatalf("signature verify returned false")
	}
}

func TestSM2_StringHex_EncryptDecrypt_SignVerify(t *testing.T) {
	pubHex, privHex, err := GenerateKeyPairHex()
	if err != nil {
		t.Fatalf("GenerateKeyPairHex failed: %v", err)
	}

	msg := "hello sm2 string hex"

	// Encrypt -> Hex output
	ctHex, err := EncryptDefault(msg, pubHex)
	if err != nil {
		t.Fatalf("EncryptDefault failed: %v", err)
	}

	// Decrypt
	pt, err := Decrypt(ctHex, privHex)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if pt != msg {
		t.Fatalf("Decrypt returned mismatch: got %q want %q", pt, msg)
	}

	// EncryptSign (Hex)
	pair, err := EncryptSignDefault(msg, pubHex, privHex)
	if err != nil {
		t.Fatalf("EncryptSignDefault failed: %v", err)
	}

	// Verify signature over ciphertext
	ok, err := Verify(pair.Ciphertext, pubHex, pair.Signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatalf("signature verify returned false")
	}

	// VerifyDecrypt
	dec, err := VerifyDecrypt(pair.Ciphertext, pair.Signature, pubHex, privHex)
	if err != nil {
		t.Fatalf("VerifyDecrypt failed: %v", err)
	}
	if dec != msg {
		t.Fatalf("VerifyDecrypt returned mismatch: got %q want %q", dec, msg)
	}
}

func TestSM2_StringBase64_EncryptDecrypt_SignVerify(t *testing.T) {
	pubB64, privB64, err := GenerateKeyPairBase64()
	if err != nil {
		t.Fatalf("GenerateKeyPairBase64 failed: %v", err)
	}

	msg := "hello sm2 string base64"

	// Encrypt -> Base64 output
	ctB64, err := Encrypt(msg, pubB64, true)
	if err != nil {
		t.Fatalf("Encrypt (base64) failed: %v", err)
	}

	// Decrypt
	pt, err := Decrypt(ctB64, privB64)
	if err != nil {
		t.Fatalf("Decrypt (base64) failed: %v", err)
	}
	if pt != msg {
		t.Fatalf("Decrypt returned mismatch: got %q want %q", pt, msg)
	}

	// EncryptSign (Base64)
	pair, err := EncryptSign(msg, pubB64, privB64, true)
	if err != nil {
		t.Fatalf("EncryptSign (base64) failed: %v", err)
	}

	// Verify signature over ciphertext
	ok, err := Verify(pair.Ciphertext, pubB64, pair.Signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatalf("signature verify returned false")
	}

	// VerifyDecrypt
	dec, err := VerifyDecrypt(pair.Ciphertext, pair.Signature, pubB64, privB64)
	if err != nil {
		t.Fatalf("VerifyDecrypt failed: %v", err)
	}
	if dec != msg {
		t.Fatalf("VerifyDecrypt returned mismatch: got %q want %q", dec, msg)
	}
}
