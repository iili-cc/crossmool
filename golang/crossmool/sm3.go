package crossmool

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"hash"

	"github.com/emmansun/gmsm/sm3"
)

// Digest returns raw SM3 digest bytes
func Digest(data []byte) []byte {
	h := sm3.New()
	h.Write(data)
	return h.Sum(nil)
}

// DigestHex returns hex string of SM3 digest
func DigestHex(data []byte) string {
	return EncodeHex(Digest(data))
}

// DigestBase64 returns base64 string of SM3 digest
func DigestBase64(data []byte) string {
	return EncodeBase64(Digest(data))
}

// DigestToStr returns SM3 digest as Hex (default) or Base64 string.
// input is a string that will be encoded as UTF-8 bytes before digesting.
func DigestToStr(input string, toBase64 bool) string {
	digestBytes := Digest([]byte(input))
	if toBase64 {
		return EncodeBase64(digestBytes)
	}
	return EncodeHex(digestBytes)
}

// HMAC-SM3 using standard HMAC with SM3 as hash
func HMAC(key, data []byte) []byte {
	var mac hash.Hash = hmac.New(func() hash.Hash { return sm3.New() }, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// HMACToStr computes HMAC-SM3 with string key and data inputs.
// key must be Hex or Base64 encoded; data can be Hex, Base64, or UTF-8 string.
// Returns Hex by default, or Base64 when toBase64 is true.
func HMACToStr(key string, data string, toBase64 bool) (string, error) {
	if key == "" || data == "" {
		return "", errors.New("HMAC-SM3: key and data cannot be empty")
	}
	keyBytes, err := ConvertStringToBytes(key)
	if err != nil {
		return "", err
	}
	// data: try hex/base64 first, fallback to UTF-8
	var dataBytes []byte
	if IsHexString(data) {
		dataBytes, err = DecodeHexString(data)
		if err != nil {
			return "", err
		}
	} else if IsBase64String(data) {
		dataBytes, err = DecodeBase64String(data)
		if err != nil {
			return "", err
		}
	} else {
		dataBytes = []byte(data)
	}
	hmacBytes := HMAC(keyBytes, dataBytes)
	if toBase64 {
		return EncodeBase64(hmacBytes), nil
	}
	return EncodeHex(hmacBytes), nil
}

// GenerateHmacKey generates random bytes size >=32
func GenerateHmacKey(length int) []byte {
	if length < 32 {
		length = 32
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		// fallback to deterministic zeroed key (should not happen normally)
		for i := range b {
			b[i] = 0
		}
	}
	return b
}

// GenerateHmacKeyToStr generates a random HMAC key and returns it as
// Hex (default) or Base64 string.
func GenerateHmacKeyToStr(length int, toBase64 bool) string {
	keyBytes := GenerateHmacKey(length)
	if toBase64 {
		return EncodeBase64(keyBytes)
	}
	return EncodeHex(keyBytes)
}

// HMACVerify computes HMAC-SM3 and compares it with the received value.
func HMACVerify(key string, data string, receivedHmac string) (bool, error) {
	expected, err := HMACToStr(key, data, false)
	if err != nil {
		return false, err
	}
	return expected == receivedHmac, nil
}