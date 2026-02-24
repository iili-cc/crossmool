package crossmool

import (
    "encoding/base64"
    "encoding/hex"
    "regexp"
)

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func IsHexString(s string) bool {
    return s != "" && hexRe.MatchString(s)
}

func IsBase64String(s string) bool {
    if s == "" {
        return false
    }
    // quick length check
    if len(s)%4 != 0 {
        return false
    }
    _, err := base64.StdEncoding.DecodeString(s)
    return err == nil
}

func DecodeHexString(s string) ([]byte, error) {
    return hex.DecodeString(s)
}

func EncodeHex(data []byte) string {
    return hex.EncodeToString(data)
}

func DecodeBase64String(s string) ([]byte, error) {
    return base64.StdEncoding.DecodeString(s)
}

func EncodeBase64(data []byte) string {
    return base64.StdEncoding.EncodeToString(data)
}

// convert string (hex or base64) to bytes
func ConvertStringToBytes(s string) ([]byte, error) {
    if IsHexString(s) {
        return DecodeHexString(s)
    }
    if IsBase64String(s) {
        return DecodeBase64String(s)
    }
    return nil, ErrUnsupportedEncoding
}

// defined errors
var (
    ErrUnsupportedEncoding = &ErrString{"unsupported encoding: expect hex or base64"}
)

type ErrString struct{ s string }

func (e *ErrString) Error() string { return e.s }

func NewErrString(s string) error { return &ErrString{s} }
