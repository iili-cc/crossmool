// SM4 国密对称加密算法示例（GCM 模式）
//
// 快速上手：
//   1. cd golang/crossmool
//   2. go run ./samples/sm4_sample/
//
// 核心能力：
//   - 生成 SM4 密钥（128-bit，Hex / Base64 格式）
//   - SM4-GCM 加密（带认证标签，防篡改）
//   - SM4-GCM 解密（自动检测 Hex / Base64 输入）
//   - GCM 模式：任何篡改都会导致解密失败

package main

import (
	"fmt"
	"cc.iili.tools/crossmool"
)

func main() {
	fmt.Println("============================================================")
	fmt.Println("  SM4 Sample — 国密对称加密 (GCM 模式)")
	fmt.Println("============================================================")
	fmt.Println()

	// ==================== 原始内容 ====================
	originalContent := "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。" +
		"路过咖啡店时買了一杯美式，順便（顺便）看了下手机，" +
		"今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。" +
		"朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" " +
		"我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。"

	fmt.Printf("OriginalContent ::: %s\n", originalContent)
	fmt.Println()

	// ==================== 1. 生成 SM4 密钥 ====================
	fmt.Println(">>> 1. 生成 SM4 密钥（128-bit）")

	keyBytes, err := crossmool.GenerateKey()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	hexKey := crossmool.EncodeHex(keyBytes)
	fmt.Printf("  SM4 Hex Key    ::: %s\n", hexKey)

	base64Key := crossmool.EncodeBase64(keyBytes)
	fmt.Printf("  SM4 Base64 Key ::: %s\n", base64Key)
	fmt.Println()

	// ==================== 2. Hex 输出 GCM 加解密 ====================
	fmt.Println(">>> 2. 使用 Hex 输出进行 GCM 加解密")

	encryptedHex, err := crossmool.EncryptGcmHex(keyBytes, []byte(originalContent))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Encrypted (Hex) ::: %.150s...\n", encryptedHex)

	decryptedHex, err := crossmool.DecryptGcmToString(keyBytes, encryptedHex)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Decrypted (Hex) ::: %s\n", decryptedHex)
	fmt.Printf("  WhetherDecryptEqualsOriginalContent (Hex) ::: %t\n", originalContent == decryptedHex)
	fmt.Println()

	// ==================== 3. Base64 输出 GCM 加解密 ====================
	fmt.Println(">>> 3. 使用 Base64 输出进行 GCM 加解密")

	encryptedB64, err := crossmool.EncryptGcm(keyBytes, []byte(originalContent), true)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Encrypted (Base64) ::: %.100s...\n", encryptedB64)

	decryptedB64, err := crossmool.DecryptGcmToString(keyBytes, encryptedB64)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Decrypted (Base64) ::: %s\n", decryptedB64)
	fmt.Printf("  WhetherDecryptEqualsOriginalContent (Base64) ::: %t\n", originalContent == decryptedB64)
	fmt.Println()

	// ==================== 4. 随机 IV 验证 ====================
	fmt.Println(">>> 4. 随机 IV 验证（每次 GCM 加密密文不同）")

	ct1, err := crossmool.EncryptGcmHex(keyBytes, []byte("Same plaintext"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	ct2, err := crossmool.EncryptGcmHex(keyBytes, []byte("Same plaintext"))
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  Ciphertext 1 ::: %.50s...\n", ct1)
	fmt.Printf("  Ciphertext 2 ::: %.50s...\n", ct2)
	fmt.Printf("  IV differs (ciphertexts not equal) ::: %t\n", ct1 != ct2)
	fmt.Println()

	// ==================== 5. GCM 防篡改验证 ====================
	fmt.Println(">>> 5. GCM 防篡改验证")
	fmt.Println("  （故意篡改密文末尾字符，GCM 应检测到并拒绝解密）")

	tampered := encryptedHex[:len(encryptedHex)-2] + "XX"
	_, err = crossmool.DecryptGcmToString(keyBytes, tampered)
	if err != nil {
		fmt.Printf("  GCM detected tampering, decryption failed ::: %v\n", err)
	} else {
		fmt.Println("  Tampered decrypted (should not happen!)")
	}
	fmt.Println()

	fmt.Println("=== SM4 Sample 完成 ===")
}
