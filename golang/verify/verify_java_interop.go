package main

import (
	"fmt"
	"cc.iili.tools/crossmool"
)

func main() {
	fmt.Println("============================================================")
	fmt.Println("Java-Go SM2/SM3/SM4 Interoperability Test - Go Verifier")
	fmt.Println("============================================================\n")
	
	// Test data from Java output
	testMessage := "Hello, Java-Go Interop Test! 这是国密算法测试数据"
	
	// SM2 keys (Hex)
	sm2PubKeyHex := "3059301306072a8648ce3d020106082a811ccf5501822d03420004920db631f09a37941bd5a2308a423945973a3fd2e6bc1fccd7ac98aeb1efb2395b05ab697a5dc418ed956d5bd74d004d047dab88de0aa8846db2b8b6eefe0870"
	sm2PrivKeyHex := "308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420086f7f35c03800f0191a8265c1b402aa589eb655761942d719f494b4559924bda00a06082a811ccf5501822da14403420004920db631f09a37941bd5a2308a423945973a3fd2e6bc1fccd7ac98aeb1efb2395b05ab697a5dc418ed956d5bd74d004d047dab88de0aa8846db2b8b6eefe0870"
	
	// SM2 ciphertexts
	sm2CipherHex := "04baf82a744b8bb303450077ab5ef597c2b0acb74137ff904685cbe510e7def5186c47891032e21bb3835780d70dbca52cc1b09e1333c69d655ad6991aab88b54ca621004c0dccae91afcc9487d539d816f88ed565b6c78a60bdc8f666140e962667db00ab24e0ce2c0615a2cfa7e9f1087e442190e23f1072092ac3ffab11187c76c1f88f5f4a37c405bcc76c1716803aa062861b0ce455f4f747e1"
	sm2CipherBase64 := "BBmkOTFTkLUQ57MYsblVnhPIdZqp/RzCNXn+4fciCM0VC3tZwTlRI5UCywbSkoUZVjbru5fugorwZLpFD4EuS8jOHUxm9cedEFJ37WfCFEEwU2JGI1N3VFPz/oGi203Yd0MiO63XWcaJcORrL2XVSJvjhHvxw36pGIacB+oo2xL7RVojYiNtiZ+l8z5L6p7fYmsJMrAt4oOGQT5b"
	
	// SM2 signatures
	sm2SignHex := "30450221009f4a06765f64c52c63900665aed485fdce07bb2c6f6e4497dc7986063a7bff96022026587eb273275a5f89115a9e1eaab228412591cece08388d8d7a73fe67b8c43f"
	sm2SignBase64 := "MEYCIQDIQ1jHF7vCtK+7bend/LosdlRWWymj/nh/pDsGRJBFxwIhANeUV04nf5QNmr1LASw6GhClLuiOYTvq+aGYPdAyOfFc"
	
	// SM3 digests
	sm3DigestHex := "2a11157ec3cef911ecd97d4d717cb36ae015990f0737d8b820bc2a45fd239260"
	sm3DigestBase64 := "KhEVfsPO+RHs2X1NcXyzauAVmQ8HN9i4ILwqRf0jkmA="
	
	// HMAC-SM3
	hmacKeyHex := "4ae2b84dd8cef6a39602edfa66f07b9970c79ca86a9641f3de4b7217f08e186c"
	hmacHex := "a4c641fa9c087f5aaf6345d6cda2698745bda3db21fbceca6918f42233f454e3"
	hmacBase64 := "pMZB+pwIf1qvY0XWzaJph0W9o9sh+87KaRj0IjP0VOM="
	
	// SM4 key and ciphertexts
	sm4KeyHex := "0123456789abcdeffedcba9876543210"
	sm4CipherHex := "a47c35180b49cda8823c419473b7a629abd6eb541e96ef4303a151569a727aa86090315746fe0e14053dc28131f64a32372a989214400a869edab33362fba1830b9a4faaca778d96c6e867aac95f82d97e3e95296f5d72"
	sm4CipherBase64 := "Qsmfhw0lGf+JJ1+j97RUhTIxgwS1fY0Dbe4ZpyFi3G8lzaZa2IZe8vvTh/dkmWtvL8dHHrGYlMPUd2lQU1Vr9JMd8gqsrUBYHoDu+8+dIMcHMSSQSpCc"
	
	passed := 0
	failed := 0
	
	// ========== SM2 Tests ==========
	fmt.Println("--- SM2 Tests ---")
	
	// Test 1: SM2 Decrypt Hex
	fmt.Print("  [Test 1] SM2 Decrypt (Hex)... ")
	decHex, err := crossmool.Decrypt(sm2CipherHex, sm2PrivKeyHex)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else if decHex == testMessage {
		fmt.Println("PASS")
		passed++
	} else {
		fmt.Printf("FAIL: got '%s'\n", decHex)
		failed++
	}
	
	// Test 2: SM2 Decrypt Base64
	fmt.Print("  [Test 2] SM2 Decrypt (Base64)... ")
	decBase64, err := crossmool.Decrypt(sm2CipherBase64, sm2PrivKeyHex)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else if decBase64 == testMessage {
		fmt.Println("PASS")
		passed++
	} else {
		fmt.Printf("FAIL: got '%s'\n", decBase64)
		failed++
	}
	
	// Test 3: SM2 Verify Hex
	fmt.Print("  [Test 3] SM2 Verify (Hex)... ")
	verifyHex, err := crossmool.Verify(testMessage, sm2PubKeyHex, sm2SignHex)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else if verifyHex {
		fmt.Println("PASS")
		passed++
	} else {
		fmt.Println("FAIL: signature verification failed")
		failed++
	}
	
	// Test 4: SM2 Verify Base64
	fmt.Print("  [Test 4] SM2 Verify (Base64)... ")
	verifyBase64, err := crossmool.Verify(testMessage, sm2PubKeyHex, sm2SignBase64)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else if verifyBase64 {
		fmt.Println("PASS")
		passed++
	} else {
		fmt.Println("FAIL: signature verification failed")
		failed++
	}
	
	// ========== SM3 Tests ==========
	fmt.Println("\n--- SM3 Tests ---")
	
	// Test 5: SM3 Digest Hex
	fmt.Print("  [Test 5] SM3 Digest (Hex)... ")
	goSm3Hex := crossmool.DigestHex([]byte(testMessage))
	if goSm3Hex == sm3DigestHex {
		fmt.Println("PASS")
		passed++
	} else {
		fmt.Printf("FAIL: got '%s'\n", goSm3Hex)
		failed++
	}
	
	// Test 6: SM3 Digest Base64
	fmt.Print("  [Test 6] SM3 Digest (Base64)... ")
	goSm3Base64 := crossmool.DigestBase64([]byte(testMessage))
	if goSm3Base64 == sm3DigestBase64 {
		fmt.Println("PASS")
		passed++
	} else {
		fmt.Printf("FAIL: got '%s'\n", goSm3Base64)
		failed++
	}
	
	// ========== HMAC-SM3 Tests ==========
	fmt.Println("\n--- HMAC-SM3 Tests ---")
	
	// Test 7: HMAC-SM3 Hex
	fmt.Print("  [Test 7] HMAC-SM3 (Hex)... ")
	goHmacHex, err := crossmool.HMACToStr(hmacKeyHex, testMessage, false)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else if goHmacHex == hmacHex {
		fmt.Println("PASS")
		passed++
	} else {
		fmt.Printf("FAIL: got '%s'\n", goHmacHex)
		failed++
	}
	
	// Test 8: HMAC-SM3 Base64
	fmt.Print("  [Test 8] HMAC-SM3 (Base64)... ")
	goHmacBase64, err := crossmool.HMACToStr(hmacKeyHex, testMessage, true)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		failed++
	} else if goHmacBase64 == hmacBase64 {
		fmt.Println("PASS")
		passed++
	} else {
		fmt.Printf("FAIL: got '%s'\n", goHmacBase64)
		failed++
	}
	
	// ========== SM4 Tests ==========
	fmt.Println("\n--- SM4 GCM Tests ---")
	
	// Parse SM4 key
	sm4KeyBytes, err := crossmool.DecodeHexString(sm4KeyHex)
	if err != nil {
		fmt.Printf("  SM4 key parse error: %v\n", err)
		failed += 2
	} else {
		// Test 9: SM4 Decrypt Hex
		fmt.Print("  [Test 9] SM4 GCM Decrypt (Hex)... ")
		decSm4Hex, err := crossmool.DecryptGcmToString(sm4KeyBytes, sm4CipherHex)
		if err != nil {
			fmt.Printf("FAIL: %v\n", err)
			failed++
		} else if decSm4Hex == testMessage {
			fmt.Println("PASS")
			passed++
		} else {
			fmt.Printf("FAIL: got '%s'\n", decSm4Hex)
			failed++
		}
		
		// Test 10: SM4 Decrypt Base64
		fmt.Print("  [Test 10] SM4 GCM Decrypt (Base64)... ")
		decSm4Base64, err := crossmool.DecryptGcmToString(sm4KeyBytes, sm4CipherBase64)
		if err != nil {
			fmt.Printf("FAIL: %v\n", err)
			failed++
		} else if decSm4Base64 == testMessage {
			fmt.Println("PASS")
			passed++
		} else {
			fmt.Printf("FAIL: got '%s'\n", decSm4Base64)
			failed++
		}
	}
	
	// ========== Summary ==========
	fmt.Println("\n============================================================")
	fmt.Printf("Go Verification Summary: %d/%d tests passed\n", passed, passed+failed)
	fmt.Println("============================================================")
	
	if failed == 0 {
		fmt.Println("\n✅ [SUCCESS] All Java-Go interoperability tests passed!")
		fmt.Println("\n=== Interoperability Notes ===")
		fmt.Println("✓ SM2: Java and Go use same DER key formats (X.509/PKCS#8)")
		fmt.Println("✓ SM2: Both use C1C3C2 ciphertext format and SM3 digest")
		fmt.Println("✓ SM2: Both use same USER_ID \"1234567812345678\" for signing")
		fmt.Println("✓ SM3: Direct compatibility - identical digests")
		fmt.Println("✓ HMAC-SM3: Direct compatibility with Hex/Base64 key parsing")
		fmt.Println("✓ SM4-GCM: Both use 12-byte IV, 16-byte tag, IV+ciphertext+tag format")
		fmt.Println("✓ Encoding: Both support Hex and Base64 auto-detection")
	} else {
		fmt.Printf("\n❌ [FAIL] %d test(s) failed. Check interoperability issues.\n", failed)
	}
}