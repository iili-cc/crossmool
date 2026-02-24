package crossmool

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// GenerateKeyPair returns raw DER encoded public and private keys (X.509 / PKCS8)
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

func GenerateKeyPairHex() (pubHex string, privHex string, err error) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	return EncodeHex(pub), EncodeHex(priv), nil
}

func GenerateKeyPairBase64() (pubB64 string, privB64 string, err error) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		return "", "", err
	}
	return EncodeBase64(pub), EncodeBase64(priv), nil
}

// helper to get PublicKey object from encoded bytes (hex or base64 accepted)
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

// DecryptBytes takes raw ciphertext bytes and private key DER bytes
func DecryptBytes(ciphertext []byte, privDer []byte) ([]byte, error) {
	priv, err := parsePrivateKeyFromBytes(privDer)
	if err != nil {
		return nil, err
	}
	return sm2.Decrypt(priv, ciphertext)
}

// SignBytes signs content using private key DER bytes and returns signature bytes
func SignBytes(content []byte, privDer []byte) ([]byte, error) {
	priv, err := parsePrivateKeyFromBytes(privDer)
	if err != nil {
		return nil, err
	}
	// sm2.Sign returns big.Int r,s (uses *ecdsa.PrivateKey), encode as ASN.1
	r, s, err := sm2.Sign(rand.Reader, &priv.PrivateKey, content)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

// VerifyBytes verifies signature using public key DER bytes
func VerifyBytes(content []byte, signature []byte, pubDer []byte) (bool, error) {
	pub, err := parsePublicKeyFromBytes(pubDer)
	if err != nil {
		return false, err
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signature, &rs); err != nil {
		return false, err
	}
	return sm2.Verify(pub, content, rs.R, rs.S), nil
}
