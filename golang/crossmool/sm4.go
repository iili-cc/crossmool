package crossmool

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/emmansun/gmsm/sm4"
)

const (
	gcmIVLength  = 12 // 96 bits
	gcmTagSize   = 16 // 128 bits
	sm4KeySize   = 16 // 128 bits
	sm4BlockSize = 16
)

// ========================
// Key generation
// ========================

// GenerateKey generates a 16-byte random SM4 key.
func GenerateKey() ([]byte, error) {
	key := make([]byte, sm4KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate SM4 key: %w", err)
	}
	return key, nil
}

// ========================
// GCM mode
// ========================

// EncryptGcm encrypts plaintext using SM4-GCM with a random IV.
// Output: Hex(IV + ciphertext + Tag) by default, or Base64 when toBase64 is true.
func EncryptGcm(key, plain []byte, toBase64 bool) (string, error) {
	iv := make([]byte, gcmIVLength)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}
	return EncryptGcmWithIV(key, plain, iv, toBase64)
}

// EncryptGcmWithIV encrypts plaintext using SM4-GCM with a specific IV.
// Output: Hex(IV + ciphertext + Tag) by default, or Base64 when toBase64 is true.
func EncryptGcmWithIV(key, plain, iv []byte, toBase64 bool) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	if len(iv) != gcmIVLength {
		return "", fmt.Errorf("GCM IV must be %d bytes", gcmIVLength)
	}

	block, err := sm4.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create SM4 cipher: %w", err)
	}

	aead, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Seal appends ciphertext+tag to dst, we prepend IV
	cipherWithTag := aead.Seal(nil, iv, plain, nil)
	result := make([]byte, 0, len(iv)+len(cipherWithTag))
	result = append(result, iv...)
	result = append(result, cipherWithTag...)

	if toBase64 {
		return EncodeBase64(result), nil
	}
	return EncodeHex(result), nil
}

// EncryptGcmHex encrypts plaintext using SM4-GCM and returns Hex encoded result.
// Convenience wrapper for EncryptGcm with toBase64=false.
func EncryptGcmHex(key, plain []byte) (string, error) {
	return EncryptGcm(key, plain, false)
}

// DecryptGcm decrypts SM4-GCM ciphertext.
// Input: auto-detects Hex or Base64 encoding of (IV + ciphertext + Tag)
func DecryptGcm(key []byte, encodedData string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	data, err := ConvertStringToBytes(encodedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}
	if len(data) < gcmIVLength+gcmTagSize {
		return nil, fmt.Errorf("invalid GCM data: too short")
	}

	iv := data[:gcmIVLength]
	cipherWithTag := data[gcmIVLength:]

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM4 cipher: %w", err)
	}

	aead, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return aead.Open(nil, iv, cipherWithTag, nil)
}

// DecryptGcmHex decrypts SM4-GCM ciphertext from Hex encoded input.
// Convenience wrapper that forces Hex decoding.
func DecryptGcmHex(key []byte, hexStr string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	data, err := DecodeHexString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	if len(data) < gcmIVLength+gcmTagSize {
		return nil, fmt.Errorf("invalid GCM data: too short")
	}

	iv := data[:gcmIVLength]
	cipherWithTag := data[gcmIVLength:]

	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create SM4 cipher: %w", err)
	}

	aead, err := cipher.NewGCMWithTagSize(block, gcmTagSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return aead.Open(nil, iv, cipherWithTag, nil)
}

// DecryptGcmToString decrypts SM4-GCM ciphertext and returns a UTF-8 string.
// Input auto-detects Hex or Base64 encoding.
func DecryptGcmToString(key []byte, encodedData string) (string, error) {
	plain, err := DecryptGcm(key, encodedData)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ========================
// helpers
// ========================

func validateKey(key []byte) error {
	if len(key) != sm4KeySize {
		return fmt.Errorf("SM4 key must be %d bytes (128 bits)", sm4KeySize)
	}
	return nil
}
