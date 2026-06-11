package main

import (
	crossmool "cc.iili.tools/crossmool"
	"fmt"
)

func main() {
	derPub := "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
	msg := "hello"
	cipher, err := crossmool.Encrypt(msg, derPub, false)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}
	fmt.Printf("%s,%d", cipher, len(cipher))
}
