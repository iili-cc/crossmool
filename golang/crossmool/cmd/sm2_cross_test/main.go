package main

import (
	crossmool "cc.iili.tools/crossmool"
	"fmt"
	"os"
)

func main() {
	derPriv := "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
	derPub := "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
	msg := "Hello, 这是跨语言国密互通性测试数据"

	if len(os.Args) > 1 && os.Args[1] == "encrypt" {
		// Generate cipher
		cipher, err := crossmool.Encrypt(msg, derPub, false)
		if err != nil {
			fmt.Printf("ERROR: %v\n", err)
			return
		}
		fmt.Print(cipher)
	} else if len(os.Args) > 2 && os.Args[1] == "decrypt" {
		// Decrypt cipher from arg[2]
		cipher := os.Args[2]
		dec, err := crossmool.Decrypt(cipher, derPriv)
		if err != nil {
			fmt.Printf("DEC_FAIL: %v\n", err)
			return
		}
		fmt.Printf("DEC_OK=%v", dec == msg)
	} else {
		// Full test
		// 1. Go self
		cipher, _ := crossmool.Encrypt(msg, derPub, false)
		dec, _ := crossmool.Decrypt(cipher, derPriv)
		fmt.Printf("Go self: %v\n", dec == msg)
		
		// 2. Generate for Python
		fmt.Printf("GO_CIPHER=%s\n", cipher)
	}
}
