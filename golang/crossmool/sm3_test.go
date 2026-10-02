package crossmool

import (
	"encoding/hex"
	"testing"
)

// ========================
// SM3 Digest — GB/T 32905 standard test vectors
// ========================

func TestSM3_Digest_GB32905_ABC(t *testing.T) {
	// GB/T 32905-2016 Appendix A.1: SM3("abc")
	input := []byte("abc")
	expected := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

	got := Digest(input)
	gotHex := hex.EncodeToString(got)

	if gotHex != expected {
		t.Fatalf("SM3(\"abc\") mismatch:\n  got:  %s\n  want: %s", gotHex, expected)
	}
}

func TestSM3_Digest_GB32905_Empty(t *testing.T) {
	// GB/T 32905-2016 Appendix A.1: SM3("")
	input := []byte("")
	expected := "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"

	got := Digest(input)
	gotHex := hex.EncodeToString(got)

	if gotHex != expected {
		t.Fatalf("SM3(\"\") mismatch:\n  got:  %s\n  want: %s", gotHex, expected)
	}
}

func TestSM3_Digest_GB32905_Long(t *testing.T) {
	// GB/T 32905-2016 Appendix A.2: SM3("abcd" repeated 16 times = 64 bytes)
	input := []byte("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd")
	expected := "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"

	got := Digest(input)
	gotHex := hex.EncodeToString(got)

	if gotHex != expected {
		t.Fatalf("SM3(64-byte) mismatch:\n  got:  %s\n  want: %s", gotHex, expected)
	}
}

func TestSM3_Digest_SingleByte(t *testing.T) {
	// Edge case: single byte input
	input := []byte{0x61} // "a"
	got := Digest(input)

	// Should produce 32-byte hash
	if len(got) != 32 {
		t.Fatalf("SM3 digest length should be 32 bytes, got %d", len(got))
	}
}

func TestSM3_Digest_Large(t *testing.T) {
	// Edge case: 1KB input
	input := make([]byte, 1024)
	for i := range input {
		input[i] = byte(i % 256)
	}

	got := Digest(input)

	if len(got) != 32 {
		t.Fatalf("SM3 digest length should be 32 bytes, got %d", len(got))
	}
}

// ========================
// SM3 DigestHex / DigestBase64
// ========================

func TestSM3_DigestHex(t *testing.T) {
	input := []byte("Hello, SM3")

	got := DigestHex(input)

	if !IsHexString(got) {
		t.Fatalf("DigestHex should return valid hex string, got: %s", got)
	}
	if len(got) != 64 {
		t.Fatalf("DigestHex length should be 64 (32 bytes hex), got %d", len(got))
	}
}

func TestSM3_DigestBase64(t *testing.T) {
	input := []byte("Hello, SM3")

	got := DigestBase64(input)

	if !IsBase64String(got) {
		t.Fatalf("DigestBase64 should return valid base64 string, got: %s", got)
	}
	if len(got) != 44 {
		t.Fatalf("DigestBase64 length should be 44 (32 bytes base64), got %d", len(got))
	}
}

func TestSM3_DigestHex_Consistency(t *testing.T) {
	input := []byte("same input")
	hex1 := DigestHex(input)
	hex2 := DigestHex(input)

	if hex1 != hex2 {
		t.Fatalf("DigestHex determinism failed:\n  call1: %s\n  call2: %s", hex1, hex2)
	}

	// Verify Digest and DigestHex agree
	raw := Digest(input)
	rawHex := hex.EncodeToString(raw)
	if hex1 != rawHex {
		t.Fatalf("DigestHex disagrees with Digest:\n  DigestHex: %s\n  Digest->hex: %s", hex1, rawHex)
	}
}

// ========================
// SM3 DigestToStr (string input convenience)
// ========================

func TestSM3_DigestToStr_Hex(t *testing.T) {
	input := "Hello, 這是SM3測試"
	got := DigestToStr(input, false)

	if !IsHexString(got) {
		t.Fatalf("DigestToStr(hex) should return valid hex, got: %s", got)
	}
	if len(got) != 64 {
		t.Fatalf("DigestToStr(hex) should return 64 hex chars, got %d: %s", len(got), got)
	}

	// Should match raw Digest
	rawHex := hex.EncodeToString(Digest([]byte(input)))
	if got != rawHex {
		t.Fatalf("DigestToStr disagrees with Digest:\n  DigestToStr: %s\n  Digest->hex: %s", got, rawHex)
	}
}

func TestSM3_DigestToStr_Base64(t *testing.T) {
	input := "Hello, 這是SM3測試"
	got := DigestToStr(input, true)

	if !IsBase64String(got) {
		t.Fatalf("DigestToStr(base64) should return valid base64, got: %s", got)
	}

	// Should match raw Digest
	rawB64 := EncodeBase64(Digest([]byte(input)))
	if got != rawB64 {
		t.Fatalf("DigestToStr disagrees with Digest:\n  DigestToStr: %s\n  Digest->b64: %s", got, rawB64)
	}
}

func TestSM3_DigestToStr_Empty(t *testing.T) {
	got := DigestToStr("", false)

	if !IsHexString(got) {
		t.Fatalf("DigestToStr on empty string should return valid hex, got: %s", got)
	}
	if len(got) != 64 {
		t.Fatalf("DigestToStr on empty string should return 64 chars, got %d", len(got))
	}
}

// ========================
// SM3 Chinese text / interoperability
// ========================

func TestSM3_Digest_Chinese_Interop(t *testing.T) {
	// Cross-language interoperability test vector
	msg := "Hello, 这是跨语言国密互通性测试数据"
	expected := "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"

	got := Digest([]byte(msg))
	gotHex := hex.EncodeToString(got)

	if gotHex != expected {
		t.Fatalf("SM3 interop mismatch:\n  got:  %s\n  want: %s", gotHex, expected)
	}
}

// ========================
// HMAC-SM3 — basic tests
// ========================

func TestSM3_HMAC_Basic(t *testing.T) {
	key := []byte("my-secret-key")
	data := []byte("Hello, HMAC-SM3")

	mac := HMAC(data, key)

	if len(mac) != 32 {
		t.Fatalf("HMAC-SM3 length should be 32 bytes, got %d", len(mac))
	}
}

func TestSM3_HMAC_Determinism(t *testing.T) {
	key := []byte("fixed-key-12345678901234567890123456")
	data := []byte("fixed message")

	mac1 := HMAC(data, key)
	mac2 := HMAC(data, key)

	if string(mac1) != string(mac2) {
		t.Fatalf("HMAC determinism failed")
	}
}

func TestSM3_HMAC_EmptyData(t *testing.T) {
	key := []byte("some-key")
	data := []byte("")

	mac := HMAC(data, key)

	if len(mac) != 32 {
		t.Fatalf("HMAC on empty data should produce 32-byte output, got %d", len(mac))
	}
}

func TestSM3_HMAC_DifferentKeyDifferentMAC(t *testing.T) {
	data := []byte("same message")
	key1 := []byte("key-aaaaaaaaaaaaaaaaaaaaaaaaaa")
	key2 := []byte("key-bbbbbbbbbbbbbbbbbbbbbbbbbb")

	mac1 := HMAC(data, key1)
	mac2 := HMAC(data, key2)

	if string(mac1) == string(mac2) {
		t.Fatal("HMAC with different keys should produce different outputs")
	}
}

// ========================
// HMAC-SM3 — interop test vector
// ========================

func TestSM3_HMAC_Interop(t *testing.T) {
	keyHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	msg := "Hello, 这是跨语言国密互通性测试数据"
	expected := "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"

	key, _ := hex.DecodeString(keyHex)

	mac := HMAC([]byte(msg), key)
	macHex := hex.EncodeToString(mac)

	if macHex != expected {
		t.Fatalf("HMAC-SM3 interop mismatch:\n  got:  %s\n  want: %s", macHex, expected)
	}
}

// ========================
// HMACToStr — string convenience
// ========================

func TestSM3_HMACToStr_Hex(t *testing.T) {
	key := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	data := "Hello, 这是跨语言国密互通性测试数据"

	mac, err := HMACToStr(data, key, false)
	if err != nil {
		t.Fatalf("HMACToStr failed: %v", err)
	}

	if !IsHexString(mac) {
		t.Fatalf("HMACToStr(hex) should return valid hex, got: %s", mac)
	}
	if len(mac) != 64 {
		t.Fatalf("HMACToStr(hex) should return 64 chars, got %d", len(mac))
	}
}

func TestSM3_HMACToStr_Base64(t *testing.T) {
	key := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	data := "Hello, 这是跨语言国密互通性测试数据"

	mac, err := HMACToStr(data, key, true)
	if err != nil {
		t.Fatalf("HMACToStr(base64) failed: %v", err)
	}

	if !IsBase64String(mac) {
		t.Fatalf("HMACToStr(base64) should return valid base64, got: %s", mac)
	}
}

func TestSM3_HMACToStr_UTF8Data(t *testing.T) {
	// HMACToStr key must be Hex/Base64; data falls back to UTF-8
	key := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	data := "测试数据test data 中文"

	mac, err := HMACToStr(data, key, false)
	if err != nil {
		t.Fatalf("HMACToStr with UTF-8 data failed: %v", err)
	}

	if len(mac) != 64 {
		t.Fatalf("HMACToStr should return 64 hex chars, got %d", len(mac))
	}
}

func TestSM3_HMACToStr_Base64Key(t *testing.T) {
	key := "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=" // base64 of the hex key above
	data := "Hello, 跨语言测试"

	mac, err := HMACToStr(data, key, false)
	if err != nil {
		t.Fatalf("HMACToStr with base64 key failed: %v", err)
	}

	if len(mac) != 64 {
		t.Fatalf("HMACToStr should return 64 hex chars, got %d", len(mac))
	}
}

func TestSM3_HMACToStr_Consistency(t *testing.T) {
	// Same key+data in hex vs raw bytes should give same HMAC
	keyHex := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	data := "Hello, SM3 HMAC"

	// Via string API
	macStr, err := HMACToStr(data, keyHex, false)
	if err != nil {
		t.Fatalf("HMACToStr failed: %v", err)
	}

	// Via raw bytes API
	keyBytes, _ := hex.DecodeString(keyHex)
	macRaw := HMAC([]byte(data), keyBytes)
	macRawHex := hex.EncodeToString(macRaw)

	if macStr != macRawHex {
		t.Fatalf("HMACToStr disagrees with HMAC:\n  HMACToStr: %s\n  HMAC:      %s", macStr, macRawHex)
	}
}

func TestSM3_HMACToStr_EmptyKey(t *testing.T) {
	_, err := HMACToStr("some data", "", false)
	if err == nil {
		t.Fatal("HMACToStr with empty key should return error")
	}
}

func TestSM3_HMACToStr_EmptyData(t *testing.T) {
	_, err := HMACToStr("", "0102030405060708090a0b0c0d0e0f10", false)
	if err == nil {
		t.Fatal("HMACToStr with empty data should return error")
	}
}

// ========================
// GenerateHmacKey / GenerateHmacKeyToStr
// ========================

func TestSM3_GenerateHmacKey_Default(t *testing.T) {
	key := GenerateHmacKey(32)

	if len(key) != 32 {
		t.Fatalf("GenerateHmacKey(32) should return 32 bytes, got %d", len(key))
	}
}

func TestSM3_GenerateHmacKey_MinLength(t *testing.T) {
	// Requesting less than 32 should still return 32
	key := GenerateHmacKey(10)

	if len(key) != 32 {
		t.Fatalf("GenerateHmacKey(10) should return at least 32 bytes, got %d", len(key))
	}
}

func TestSM3_GenerateHmacKey_Long(t *testing.T) {
	key := GenerateHmacKey(64)

	if len(key) != 64 {
		t.Fatalf("GenerateHmacKey(64) should return 64 bytes, got %d", len(key))
	}
}

func TestSM3_GenerateHmacKey_Randomness(t *testing.T) {
	key1 := GenerateHmacKey(32)
	key2 := GenerateHmacKey(32)

	// Extremely unlikely two random 32-byte keys are identical
	if string(key1) == string(key2) {
		t.Fatal("two GenerateHmacKey calls returned identical keys (extremely unlikely)")
	}
}

func TestSM3_GenerateHmacKeyToStr_Hex(t *testing.T) {
	got := GenerateHmacKeyToStr(32, false)

	if !IsHexString(got) {
		t.Fatalf("GenerateHmacKeyToStr(hex) should return valid hex, got: %s", got)
	}
	if len(got) != 64 {
		t.Fatalf("GenerateHmacKeyToStr(hex) should return 64 chars for 32-byte key, got %d", len(got))
	}
}

func TestSM3_GenerateHmacKeyToStr_Base64(t *testing.T) {
	got := GenerateHmacKeyToStr(32, true)

	if !IsBase64String(got) {
		t.Fatalf("GenerateHmacKeyToStr(base64) should return valid base64, got: %s", got)
	}
}

func TestSM3_GenerateHmacKeyToStr_Randomness(t *testing.T) {
	s1 := GenerateHmacKeyToStr(32, false)
	s2 := GenerateHmacKeyToStr(32, false)

	if s1 == s2 {
		t.Fatal("two GenerateHmacKeyToStr calls returned identical strings (extremely unlikely)")
	}
}
