package main

import (
	crossmool "cc.iili.tools/crossmool"
	"fmt"
)

func main() {
	pubHex, privHex, err := crossmool.GenerateKeyPairHex()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return
	}
	fmt.Printf("PUB_DER_HEX=%s\n", pubHex)
	fmt.Printf("PRIV_DER_HEX=%s\n", privHex)
	fmt.Printf("PUB_LEN=%d\n", len(pubHex))
	fmt.Printf("PRIV_LEN=%d\n", len(privHex))
}
