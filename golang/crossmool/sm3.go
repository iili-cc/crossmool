package crossmool

import (
    "crypto/hmac"
    "crypto/rand"
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

// HMAC-SM3 using standard HMAC with SM3 as hash
func HMAC(key, data []byte) []byte {
    var mac hash.Hash = hmac.New(func() hash.Hash { return sm3.New() }, key)
    mac.Write(data)
    return mac.Sum(nil)
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
