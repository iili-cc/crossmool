// SM3 国密哈希算法示例
//
// 快速上手：
//   1. cd golang/crossmool
//   2. go run ./samples/sm3_sample/
//
// 核心能力：
//   - SM3 消息摘要（256-bit，类似 SHA-256）
//   - HMAC-SM3 消息认证码（防篡改 + 防伪造）
//   - 支持 Hex / Base64 输出

package main

import (
	"fmt"
	"cc.iili.tools/crossmool"
)

func main() {
	fmt.Println("============================================================")
	fmt.Println("  SM3 Sample — 国密哈希算法 (256-bit)")
	fmt.Println("============================================================")
	fmt.Println()

	// ==================== 1. SM3 消息摘要 ====================
	fmt.Println(">>> 1. SM3 消息摘要 (Digest)")

	input := "在这个全球化时代，無論身處何地，" +
		"learning and growth are always the keys to a fulfilling life."

	fmt.Printf("  Input        ::: %s\n", input)

	hash := crossmool.DigestToStr(input, false)
	fmt.Printf("  SM3 Hash     ::: %s\n", hash)

	// 显式指定 Hex 输出（与默认行为一致）
	hashHex := crossmool.DigestToStr(input, false)
	fmt.Printf("  SM3 Hash (Hex) ::: %s\n", hashHex)

	equals := hash == hashHex
	fmt.Printf("  Whether Hash Equals Hex ::: %t\n", equals)
	fmt.Println()

	// ==================== 2. HMAC-SM3 消息认证码 ====================
	fmt.Println(">>> 2. HMAC-SM3 消息认证码")

	// 生成 HMAC 密钥（32 字节 = 256-bit）
	hmacKey := crossmool.GenerateHmacKeyToStr(32, false)
	fmt.Printf("  HMAC Key      ::: %s\n", hmacKey)

	// 计算 HMAC（Hex 输出）
	hmacValue, err := crossmool.HMACToStr(hmacKey, input, false)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  HMAC Value    ::: %s\n", hmacValue)

	// 相同密钥 + 相同输入 → 相同输出（确定性）
	hmacValue2, err := crossmool.HMACToStr(hmacKey, input, false)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  HMAC Value 2  ::: %s\n", hmacValue2)

	hmacEquals := hmacValue == hmacValue2
	fmt.Printf("  Whether HMAC Values Equal ::: %t\n", hmacEquals)
	fmt.Println()

	// ==================== 3. HMAC 校验 ====================
	fmt.Println(">>> 3. HMAC 校验（防篡改验证）")

	hmacVerified, err := crossmool.HMACVerify(hmacKey, input, hmacValue)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  HMAC Verify (correct)   ::: %t\n", hmacVerified)

	// 篡改消息后校验失败
	hmacTampered, err := crossmool.HMACVerify(hmacKey, input+"X", hmacValue)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("  HMAC Verify (tampered)  ::: %t\n", hmacTampered)
	fmt.Println()

	// ==================== 4. 字节数组输入 ====================
	fmt.Println(">>> 4. 字节数组摘要（非字符串场景）")

	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	digestHex := crossmool.DigestHex(data)

	fmt.Print("  Input (5 bytes): ")
	for _, b := range data {
		fmt.Printf("%02x ", b)
	}
	fmt.Println()
	fmt.Printf("  Digest (HEX)  : %s\n", digestHex)
	fmt.Println()

	// ==================== 5. Base64 输出示例 ====================
	fmt.Println(">>> 5. Base64 格式输出（可选）")

	hashB64 := crossmool.DigestToStr(input, true)
	fmt.Printf("  SM3 Hash (Base64) ::: %s\n", hashB64)

	hmacKeyB64 := crossmool.GenerateHmacKeyToStr(32, true)
	fmt.Printf("  HMAC Key (Base64) ::: %s\n", hmacKeyB64)
	fmt.Println()

	fmt.Println("=== SM3 Sample 完成 ===")
}
