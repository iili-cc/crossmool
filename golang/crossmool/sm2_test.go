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
