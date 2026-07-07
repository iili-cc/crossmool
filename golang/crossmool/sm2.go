package crossmool

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// GenerateKeyPair returns raw DER-encoded public and private keys.
//
// The public key is encoded as X.509 SubjectPublicKeyInfo (PKIX) and the
// private key is encoded as PKCS#8. Both encodings are SM2-aware and produced
// using the gmsm `smx509` helpers so they can be parsed by SM2-aware parsers.
func GenerateKeyPair() (pubDer []byte, privDer []byte, err error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	// priv is *sm2.PrivateKey which embeds ecdsa.PrivateKey
	pub := &priv.PublicKey

	pubDER, err := smx509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}

	// Marshal private as PKCS8 using the underlying ecdsa.PrivateKey
	// marshal as SM2-aware PKCS#8 using smx509 helpers
	privDER, err := smx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pubDER, privDER, nil
}

// GenerateKeyPairHex is a convenience wrapper around GenerateKeyPair that
// returns the generated public/private key pair encoded as Hex strings.
func GenerateKeyPairHex() (pubHex string, privHex string, err error) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	return EncodeHex(pub), EncodeHex(priv), nil
}

// GenerateKeyPairBase64 is a convenience wrapper around GenerateKeyPair that
// returns the generated public/private key pair encoded as Base64 strings.
func GenerateKeyPairBase64() (pubB64 string, privB64 string, err error) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	return EncodeBase64(pub), EncodeBase64(priv), nil
}

// helper to get PublicKey object from encoded bytes (hex or base64 accepted)
//
// This function is internal and attempts to parse SM2-aware PKIX public key
// bytes using `smx509.ParsePKIXPublicKey`.
func parsePublicKeyFromBytes(b []byte) (*ecdsa.PublicKey, error) {
	// try SM2-aware PKIX parse
	pk, err := smx509.ParsePKIXPublicKey(b)
	if err == nil {
		if pub, ok := pk.(*ecdsa.PublicKey); ok {
			return pub, nil
		}
	}
	return nil, errors.New("failed to parse sm2 public key")
}

func parsePrivateKeyFromBytes(b []byte) (*sm2.PrivateKey, error) {
	// try SM2-aware PKCS#8 parse
	key, err := smx509.ParsePKCS8PrivateKey(b)
	if err == nil {
		if kp, ok := key.(*sm2.PrivateKey); ok {
			return kp, nil
		}
		if ecdsaPriv, ok := key.(*ecdsa.PrivateKey); ok {
			return &sm2.PrivateKey{PrivateKey: *ecdsaPriv}, nil
		}
	}
	// try SEC1 EC private key parse (SM2 aware)
	if kp2, err2 := smx509.ParseSM2PrivateKey(b); err2 == nil {
		return kp2, nil
	}
	return nil, errors.New("failed to parse sm2 private key")
}

// EncryptBytes takes raw content and public key in DER bytes
func EncryptBytes(content []byte, pubDer []byte) ([]byte, error) {
	pub, err := parsePublicKeyFromBytes(pubDer)
	if err != nil {
		return nil, err
	}
	// use library Encrypt with randomness and plain encrypter opts (C1C3C2)
	opts := sm2.NewPlainEncrypterOpts(sm2.MarshalUncompressed, sm2.C1C3C2)
	return sm2.Encrypt(rand.Reader, pub, content, opts)
}

// DecryptBytes decrypts SM2 ciphertext using a private key in DER form.
//
// `ciphertext` is the raw SM2 ciphertext bytes and `privDer` is the private
// key encoded in a PKCS#8 or SEC1 format that `smx509` can parse.
func DecryptBytes(ciphertext []byte, privDer []byte) ([]byte, error) {
	priv, err := parsePrivateKeyFromBytes(privDer)
	if err != nil {
		return nil, err
	}
	return sm2.Decrypt(priv, ciphertext)
}

// defaultSM2UserID is the default USER_ID used for SM2 signing/verification,
// matching Java BouncyCastle's default "1234567812345678" (GB/T 32918 standard).
var defaultSM2UserID = []byte("1234567812345678")

// SignBytes signs `content` using a private key provided as DER bytes and
// returns the signature as ASN.1-encoded (r,s) bytes.
//
// The private key DER may be PKCS#8 or SEC1 and will be parsed via `smx509`.
// Signing uses the SM2 standard USER_ID "1234567812345678" to match Java
// BouncyCastle's behavior.
func SignBytes(content []byte, privDer []byte) ([]byte, error) {
	priv, err := parsePrivateKeyFromBytes(privDer)
	if err != nil {
		return nil, err
	}
	// sm2.SignWithSM2 follows GB/T 32918.2-2016, includes ZA calculation with uid
	r, s, err := sm2.SignWithSM2(rand.Reader, &priv.PrivateKey, defaultSM2UserID, content)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// VerifyBytes verifies an ASN.1-encoded (r,s) signature against `content`
// using the public key in DER-encoded PKIX form. Verification uses the SM2
// standard USER_ID "1234567812345678" to match Java BouncyCastle's behavior.
func VerifyBytes(content []byte, signature []byte, pubDer []byte) (bool, error) {
	pub, err := parsePublicKeyFromBytes(pubDer)
	if err != nil {
		return false, err
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signature, &rs); err != nil {
		return false, err
	}
	return sm2.VerifyWithSM2(pub, defaultSM2UserID, content, rs.R, rs.S), nil
}

// CiphertextSignaturePair bundles ciphertext and signature strings as returned
// by the string-level convenience APIs.
type CiphertextSignaturePair struct {
	Ciphertext string
	Signature  string
}

// --- String-level convenience wrappers (Hex/Base64 + UTF-8 plaintext) ---

// Encrypt encrypts the UTF-8 `content` string using the provided public key
// string `encPublicKey` (accepted formats: Hex or Base64). The returned
// ciphertext is encoded as Hex by default, or Base64 when `toBase64` is true.
func Encrypt(content string, encPublicKey string, toBase64 bool) (string, error) {
	if encPublicKey == "" {
		return "", errors.New("sm2 encrypt error: public key is empty")
	}
	pubDer, err := ConvertStringToBytes(encPublicKey)
	if err != nil {
		return "", err
	}
	plaintext := []byte(content)
	ct, err := EncryptBytes(plaintext, pubDer)
	if err != nil {
		return "", err
	}
	if toBase64 {
		return EncodeBase64(ct), nil
	}
	return EncodeHex(ct), nil
}

// EncryptDefault encrypts `content` and returns the ciphertext as a Hex
// string. This is a convenience wrapper around `Encrypt` with `toBase64=false`.
func EncryptDefault(content string, encPublicKey string) (string, error) {
	return Encrypt(content, encPublicKey, false)
}

// Decrypt decrypts a ciphertext string (Hex or Base64 auto-detected) using
// the provided private key string (Hex or Base64). The returned value is the
// plaintext decoded as a UTF-8 string.
func Decrypt(ciphertext string, privKey string) (string, error) {
	if privKey == "" {
		return "", errors.New("sm2 decrypt error: private key is empty")
	}
	ctBytes, err := ConvertStringToBytes(ciphertext)
	if err != nil {
		return "", err
	}
	privDer, err := ConvertStringToBytes(privKey)
	if err != nil {
		return "", err
	}
	pt, err := DecryptBytes(ctBytes, privDer)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// Sign signs the UTF-8 `content` using the provided private key string
// (Hex or Base64). The signature is returned as a Hex string by default, or
// as Base64 when `toBase64` is true. The signature format is ASN.1 (r,s).
func Sign(content string, signPrivateKey string, toBase64 bool) (string, error) {
	if signPrivateKey == "" {
		return "", errors.New("sm2 sign error: private key is empty")
	}
	privDer, err := ConvertStringToBytes(signPrivateKey)
	if err != nil {
		return "", err
	}
	sigBytes, err := SignBytes([]byte(content), privDer)
	if err != nil {
		return "", err
	}
	if toBase64 {
		return EncodeBase64(sigBytes), nil
	}
	return EncodeHex(sigBytes), nil
}

// SignDefault signs `content` and returns the signature as a Hex string.
func SignDefault(content string, signPrivateKey string) (string, error) {
	return Sign(content, signPrivateKey, false)
}

// Verify verifies a signature string (Hex or Base64) over `content` using the
// provided public key string (Hex or Base64). The signature must be ASN.1
// (r,s) encoded.
func Verify(content string, publicKey string, signature string) (bool, error) {
	if publicKey == "" {
		return false, errors.New("sm2 verify error: public key is empty")
	}
	pubDer, err := ConvertStringToBytes(publicKey)
	if err != nil {
		return false, err
	}
	sigBytes, err := ConvertStringToBytes(signature)
	if err != nil {
		return false, err
	}
	return VerifyBytes([]byte(content), sigBytes, pubDer)
}

// EncryptSign encrypts `content` with `encPublicKey` then signs the
// ciphertext string with `signPrivateKey`. If `toBase64` is true outputs are
// Base64-encoded; otherwise they are Hex-encoded. Returns a
// `CiphertextSignaturePair` containing the ciphertext and signature strings.
func EncryptSign(content string, encPublicKey string, signPrivateKey string, toBase64 bool) (*CiphertextSignaturePair, error) {
	ct, err := Encrypt(content, encPublicKey, toBase64)
	if err != nil {
		return nil, err
	}
	// sign the ciphertext string (as Java implementation does)
	sig, err := Sign(ct, signPrivateKey, toBase64)
	if err != nil {
		return nil, err
	}
	return &CiphertextSignaturePair{Ciphertext: ct, Signature: sig}, nil
}

// EncryptSignDefault encrypts and signs `content`, returning Hex-encoded
// ciphertext and signature. It is a convenience wrapper for
// `EncryptSign(..., toBase64=false)`.
func EncryptSignDefault(content string, encPublicKey string, signPrivateKey string) (*CiphertextSignaturePair, error) {
	return EncryptSign(content, encPublicKey, signPrivateKey, false)
}

// VerifyDecrypt verifies `signature` over `ciphertext` using `signPublicKey`.
// If verification succeeds the function decrypts `ciphertext` using
// `decPrivateKey` and returns the plaintext string. This mirrors the
// Java `SM2Util.verifyDecrypt` convenience method.
func VerifyDecrypt(ciphertext string, signature string, signPublicKey string, decPrivateKey string) (string, error) {
	ok, err := Verify(ciphertext, signPublicKey, signature)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("sm2 verify failed")
	}
	return Decrypt(ciphertext, decPrivateKey)
}

// EncryptSignWithHexKeys expects both `encPublicKey` and `signPrivateKey` to
// be Hex strings and returns Hex-encoded ciphertext and signature. This is a
// direct parity helper for the Java `encryptSignWithHexKeys` API.
func EncryptSignWithHexKeys(content string, encPublicKey string, signPrivateKey string) (*CiphertextSignaturePair, error) {
	hexEncPublicKey := IsHexString(encPublicKey)
	hexSignPrivateKey := IsHexString(signPrivateKey)
	if hexEncPublicKey && hexSignPrivateKey {
		return EncryptSign(content, encPublicKey, signPrivateKey, false)
	}
	return nil, errors.New("sm2 encryptSignWithHexKeys error: the encPublicKey and signPrivateKey must be both Hex string.")
}

// EncryptSignWithBase64Keys expects both `encPublicKey` and `signPrivateKey`
// to be Base64 strings and returns Base64-encoded ciphertext and signature.
func EncryptSignWithBase64Keys(content string, encPublicKey string, signPrivateKey string) (*CiphertextSignaturePair, error) {
	base64EncPublicKey := IsBase64String(encPublicKey)
	base64SignPrivateKey := IsBase64String(signPrivateKey)
	if base64EncPublicKey && base64SignPrivateKey {
		return EncryptSign(content, encPublicKey, signPrivateKey, true)
	}
	return nil, errors.New("sm2 encryptSignWithBase64Keys error: the encPublicKey and signPrivateKey must be both Base64 string.")
}

// EncryptSignWithSameFormatKeys accepts keys that are either both Hex or
// both Base64 and returns ciphertext/signature encoded in the same format as
// the input keys. This mirrors the Java `encryptSignWithSameFormatKeys`.
func EncryptSignWithSameFormatKeys(content string, encPublicKey string, signPrivateKey string) (*CiphertextSignaturePair, error) {
	hexEncPublicKey := IsHexString(encPublicKey)
	hexSignPrivateKey := IsHexString(signPrivateKey)
	if hexEncPublicKey && hexSignPrivateKey {
		return EncryptSign(content, encPublicKey, signPrivateKey, false)
	}
	base64EncPublicKey := IsBase64String(encPublicKey)
	base64SignPrivateKey := IsBase64String(signPrivateKey)
	if base64EncPublicKey && base64SignPrivateKey {
		return EncryptSign(content, encPublicKey, signPrivateKey, true)
	}
	return nil, errors.New("sm2 encryptSignWithSameFormatKeys error: the encPublicKey and signPrivateKey must be both Hex string or both Base64 string.")
}

// VerifyDecryptPair verifies a `CiphertextSignaturePair` with `signPublicKey`
// and, on successful verification, decrypts the ciphertext using
// `decPrivateKey` returning the plaintext string. Utility wrapper for the
// paired workflow.
func VerifyDecryptPair(pair *CiphertextSignaturePair, signPublicKey string, decPrivateKey string) (string, error) {
	if pair == nil {
		return "", errors.New("sm2 verifyDecryptPair error: nil pair")
	}
	return VerifyDecrypt(pair.Ciphertext, pair.Signature, signPublicKey, decPrivateKey)
}

// ExportPublicKeyPEM encodes DER public key bytes to PEM format (X.509 SubjectPublicKeyInfo).
func ExportPublicKeyPEM(pubDer []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
}

// ExportPrivateKeyPEM encodes DER private key bytes to PEM format (PKCS#8 PrivateKeyInfo).
func ExportPrivateKeyPEM(privDer []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDer})
}

// ImportPublicKeyPEM decodes a PEM-encoded public key and returns the raw DER bytes.
func ImportPublicKeyPEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block (expected PUBLIC KEY)")
	}
	return block.Bytes, nil
}

// ImportPrivateKeyPEM decodes a PEM-encoded private key and returns the raw DER bytes.
func ImportPrivateKeyPEM(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block (expected PRIVATE KEY)")
	}
	return block.Bytes, nil
}
