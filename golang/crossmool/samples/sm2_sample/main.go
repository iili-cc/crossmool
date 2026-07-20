// SM2 国密非对称加密算法示例
//
// 快速上手：
//   1. 确保已安装 Go 1.24+
//   2. cd golang/crossmool
//   3. go run ./samples/sm2_sample/  或  go build -o sm2_sample ./samples/sm2_sample/ && ./sm2_sample
//
// 核心能力：
//   - 生成 SM2 密钥对（Hex / Base64）
//   - 公钥加密 → 私钥解密
//   - 私钥签名 → 公钥验签
//   - 先加密再签名 → 先验签再解密（防篡改 + 防抵赖）
//   - PEM 格式导入导出

package main

import (
	"fmt"
	"cc.iili.tools/crossmool"
)

func main() {
	fmt.Println("============================================================")
	fmt.Println("  SM2 Sample — 国密非对称加密 (SM2P256V1)")
	fmt.Println("============================================================")
	fmt.Println()

	// ==================== 原始内容 ====================
	originalContent := "今天天气真好，气温大约 28°C，我决定出門走走。" +
		"路过咖啡店时買了一杯美式，順便（顺便）看了下手机。" +
		"Don't forget to bring your umbrella!"

	fmt.Printf("OriginalContent ::: %s\n", originalContent)
	fmt.Println()

	// ==================== 1. 生成两对密钥 ====================
	fmt.Println(">>> 1. 生成两对 SM2 密钥（第1对加解密，第2对签名）")

	pubKey1, priKey1, err := crossmool.GenerateKeyPairHex()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	pubKey2, priKey2, err := crossmool.GenerateKeyPairHex()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("  privateKeyHex-1 ::: %s\n", priKey1)
	fmt.Printf("  publicKeyHex-1  ::: %s\n", pubKey1)
	fmt.Printf("  privateKeyHex-2 ::: %s\n", priKey2)
	fmt.Printf("  publicKeyHex-2  ::: %s\n", pubKey2)
	fmt.Println()

	// ==================== 2. 加密并签名 → 验签并解密 ====================
	fmt.Println(">>> 2. 加密并签名 → 验签并解密（先加密再签名，先验签再解密）")

	pair, err := crossmool.EncryptSignDefault(originalContent, pubKey1, priKey2)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("  CipherText ::: %.150s...\n", pair.Ciphertext)
	fmt.Printf("  Signature  ::: %s\n", pair.Signature)
	fmt.Println()

	verifyDecrypt, err := crossmool.VerifyDecrypt(pair.Ciphertext, pair.Signature, pubKey2, priKey1)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	fmt.Printf("  VerifyDecrypt ::: %s\n", verifyDecrypt)
	fmt.Printf("  WhetherVerifyDecryptEqualsOriginalContent ::: %t\n", originalContent == verifyDecrypt)
	fmt.Println()

	// ==================== 3. 仅加密/解密 ====================
	fmt.Println(">>> 3. 公钥加密 → 私钥解密")

	encryptedContent, err := crossmool.EncryptDefault(originalContent, pubKey1)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  EncryptedContent ::: %.150s...\n", encryptedContent)

	decryptedContent, err := crossmool.Decrypt(encryptedContent, priKey1)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  DecryptedContent ::: %s\n", decryptedContent)
	fmt.Printf("  WhetherDecryptEqualsOriginalContent ::: %t\n", originalContent == decryptedContent)
	fmt.Println()

	// ==================== 4. 签名/验签 ====================
	fmt.Println(">>> 4. 私钥签名 → 公钥验签")

	contentSignature, err := crossmool.SignDefault(originalContent, priKey2)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  ContentSignature ::: %s\n", contentSignature)

	verify, err := crossmool.Verify(originalContent, pubKey2, contentSignature)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  WhetherVerifyEqualsOriginalContent ::: %t\n", verify)
	fmt.Println()

	// ==================== 5. Base64 格式示例 ====================
	fmt.Println(">>> 5. Base64 格式输出（可选）")

	encryptedB64, err := crossmool.Encrypt(originalContent, pubKey1, true)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Encrypted (Base64) ::: %.100s...\n", encryptedB64)

	signatureB64, err := crossmool.Sign(originalContent, priKey2, true)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Signature  (Base64) ::: %s\n", signatureB64)
	fmt.Println()

	// ==================== 6. PEM 导出示例 ====================
	fmt.Println(">>> 6. PEM 格式（跨语言密钥交换）")

	pubDer, priDer, err := crossmool.GenerateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	pubPEM := crossmool.ExportPublicKeyPEM(pubDer)
	priPEM := crossmool.ExportPrivateKeyPEM(priDer)
	fmt.Printf("  Public Key PEM:\n%s", string(pubPEM))
	fmt.Printf("  Private Key PEM:\n%s", string(priPEM))

	importedPub, err := crossmool.ImportPublicKeyPEM(pubPEM)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  PEM Roundtrip ::: %t\n", crossmool.EncodeHex(importedPub) == crossmool.EncodeHex(pubDer))
	fmt.Println()

	fmt.Println("=== SM2 Sample 完成 ===")
}
