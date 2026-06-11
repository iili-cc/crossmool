package main

import (
	"cc.iili.tools/crossmool"
	"fmt"
)

func main() {
	msg := "Hello, 这是跨语言国密互通性测试数据"
	hmacKey := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

	digHex := crossmool.DigestToStr(msg, false)
	fmt.Printf("Go SM3:       %s\n", digHex)

	hmacHex, _ := crossmool.HMACToStr(hmacKey, msg, false)
	fmt.Printf("Go SM3-HMAC:  %s\n", hmacHex)

	fmt.Println()
	fmt.Println("Python SM3:      0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b")
	fmt.Println("Python SM3-HMAC: 3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6")

	pySM3 := "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
	pyHMAC := "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"

	if digHex == pySM3 {
		fmt.Println("\nSM3: PASS (Go == Python)")
	} else {
		fmt.Println("\nSM3: FAIL")
	}
	if hmacHex == pyHMAC {
		fmt.Println("SM3-HMAC: PASS (Go == Python)")
	} else {
		fmt.Println("SM3-HMAC: FAIL")
	}
}
