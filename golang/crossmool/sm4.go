package crossmool

import (
	"bytes"
	"errors"

	"github.com/emmansun/gmsm/sm4"
)

const sm4BlockSize = 16

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("invalid padding size")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-padding], nil
}

// EncryptECB encrypts data using SM4 ECB with PKCS7 padding and returns raw bytes
func EncryptECB(key []byte, data []byte) ([]byte, error) {
	if len(key) != sm4BlockSize {
		return nil, errors.New("sm4 key must be 16 bytes")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(data, sm4BlockSize)
	out := make([]byte, len(padded))
	bs := block.BlockSize()
	for i := 0; i < len(padded); i += bs {
		block.Encrypt(out[i:i+bs], padded[i:i+bs])
	}
	return out, nil
}

// DecryptECB decrypts raw SM4 ECB+PKCS7 padded bytes
func DecryptECB(key []byte, cipherText []byte) ([]byte, error) {
	if len(key) != sm4BlockSize {
		return nil, errors.New("sm4 key must be 16 bytes")
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}
	out := make([]byte, len(cipherText))
	bs := block.BlockSize()
	for i := 0; i < len(cipherText); i += bs {
		block.Decrypt(out[i:i+bs], cipherText[i:i+bs])
	}
	return pkcs7Unpad(out)
}

// wrapper signatures for Hex/Base64 handled by util functions in util.go
