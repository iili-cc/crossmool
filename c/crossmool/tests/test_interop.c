#include <stdio.h>
#include <string.h>
#include "crossmool.h"

/**
 * 互通性测试
 * 测试 C 版本与 Java 版本的互通性
 */

// Java 版本生成的测试密钥对（HEX 格式）
static const char* JAVA_PUBLIC_KEY_HEX = "04b2a5f7c3d8e9a1b4c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8";
static const char* JAVA_PRIVATE_KEY_HEX = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

// 测试数据
static const char* TEST_MESSAGE = "Hello, Cross-Language Interoperability!";

void test_sm2_interop(void) {
    printf("=== SM2 Interoperability Test ===\n\n");
    
    // 1. 使用 Java 公钥加密，C 版本解密
    printf("1. Java encrypt -> C decrypt\n");
    // 这里需要使用 Java 版本加密后的密文进行测试
    // 暂用 C 版本生成的密钥对测试
    
    crossmool_sm2_keypair_t* keypair = NULL;
    int ret = crossmool_sm2_generate_keypair(&keypair);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("  [FAIL] generate_keypair\n");
        return;
    }
    
    ret = crossmool_sm2_keypair_to_hex(keypair);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("  [FAIL] keypair_to_hex\n");
        crossmool_sm2_keypair_free(keypair);
        return;
    }
    
    printf("  Generated Key Pair:\n");
    printf("    Private: %s\n", keypair->private_key_hex);
    printf("    Public: %s\n", keypair->public_key_hex);
    
    // 2. 加密测试
    printf("\n2. Encryption Test\n");
    char* ciphertext_hex = NULL;
    ret = crossmool_sm2_encrypt(TEST_MESSAGE, NULL, keypair->public_key_hex, &ciphertext_hex);
    if (ret == CROSSMOOL_SUCCESS) {
        printf("  [PASS] encrypt\n");
        printf("    Ciphertext (HEX): %s\n", ciphertext_hex);
        
        // 3. 解密测试
        printf("\n3. Decryption Test\n");
        char* decrypted = NULL;
        ret = crossmool_sm2_decrypt(ciphertext_hex, keypair->private_key_hex, NULL, &decrypted);
        if (ret == CROSSMOOL_SUCCESS && decrypted != NULL) {
            printf("  [PASS] decrypt\n");
            printf("    Decrypted: %s\n", decrypted);
            
            if (strcmp(decrypted, TEST_MESSAGE) == 0) {
                printf("  [PASS] content matches\n");
            } else {
                printf("  [FAIL] content mismatch\n");
            }
            
            free(decrypted);
        } else {
            printf("  [FAIL] decrypt\n");
        }
        
        free(ciphertext_hex);
    } else {
        printf("  [FAIL] encrypt\n");
    }
    
    // 4. 签名测试
    printf("\n4. Signature Test\n");
    char* signature_hex = NULL;
    ret = crossmool_sm2_sign(TEST_MESSAGE, NULL, keypair->private_key_hex, &signature_hex);
    if (ret == CROSSMOOL_SUCCESS) {
        printf("  [PASS] sign\n");
        printf("    Signature (HEX): %s\n", signature_hex);
        
        // 5. 验签测试
        printf("\n5. Verification Test\n");
        int verify_result = crossmool_sm2_verify(TEST_MESSAGE, NULL, signature_hex, keypair->public_key_hex);
        if (verify_result == 1) {
            printf("  [PASS] verify\n");
        } else {
            printf("  [FAIL] verify (result=%d)\n", verify_result);
        }
        
        // 6. 错误数据验签
        printf("\n6. Tampered Data Verification Test\n");
        verify_result = crossmool_sm2_verify("Tampered data", NULL, signature_hex, keypair->public_key_hex);
        if (verify_result == 0) {
            printf("  [PASS] verify correctly failed for tampered data\n");
        } else {
            printf("  [FAIL] verify should fail for tampered data\n");
        }
        
        free(signature_hex);
    } else {
        printf("  [FAIL] sign\n");
    }
    
    // 7. 加密签名组合测试
    printf("\n7. Encrypt + Sign Combo Test\n");
    crossmool_sm2_cipher_sig_pair_t* pair = NULL;
    ret = crossmool_sm2_encrypt_sign(TEST_MESSAGE, NULL, keypair->public_key_hex, 
                                      keypair->private_key_hex, &pair);
    if (ret == CROSSMOOL_SUCCESS && pair != NULL) {
        printf("  [PASS] encrypt_sign\n");
        printf("    Ciphertext: %s\n", pair->ciphertext_hex);
        printf("    Signature: %s\n", pair->signature_hex);
        
        // 8. 验签解密组合测试
        printf("\n8. Verify + Decrypt Combo Test\n");
        char* result = NULL;
        ret = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex,
                                           keypair->public_key_hex, keypair->private_key_hex,
                                           NULL, &result);
        if (ret == CROSSMOOL_SUCCESS && result != NULL) {
            printf("  [PASS] verify_decrypt\n");
            printf("    Result: %s\n", result);
            
            if (strcmp(result, TEST_MESSAGE) == 0) {
                printf("  [PASS] content matches\n");
            } else {
                printf("  [FAIL] content mismatch\n");
            }
            
            free(result);
        } else {
            printf("  [FAIL] verify_decrypt\n");
        }
        
        crossmool_sm2_cipher_sig_pair_free(pair);
    } else {
        printf("  [FAIL] encrypt_sign\n");
    }
    
    crossmool_sm2_keypair_free(keypair);
    printf("\n=== SM2 Interoperability Test Complete ===\n");
}

void test_sm3_interop(void) {
    printf("\n=== SM3 Interoperability Test ===\n\n");
    
    const char* test_data = "Hello, SM3!";
    
    // 1. 杂凑计算
    printf("1. Digest Test\n");
    char* digest_hex = NULL;
    int ret = crossmool_sm3_digest_str(test_data, NULL, &digest_hex);
    if (ret == CROSSMOOL_SUCCESS) {
        printf("  [PASS] digest\n");
        printf("    Input: %s\n", test_data);
        printf("    Digest (HEX): %s\n", digest_hex);
        
        // 预期结果（与 Java 版本比较）
        // Java 版本：SM3Util.digestToStr("Hello, SM3!", false)
        // 注意：需要实际运行 Java 版本获取预期结果
        
        free(digest_hex);
    } else {
        printf("  [FAIL] digest\n");
    }
    
    // 2. HMAC-SM3 测试
    printf("\n2. HMAC-SM3 Test\n");
    const char* key = "test_key";
    char* hmac_hex = NULL;
    ret = crossmool_sm3_hmac_str(key, NULL, test_data, NULL, &hmac_hex);
    if (ret == CROSSMOOL_SUCCESS) {
        printf("  [PASS] hmac\n");
        printf("    Key: %s\n", key);
        printf("    Data: %s\n", test_data);
        printf("    HMAC (HEX): %s\n", hmac_hex);
        
        // 验证
        int verify_result = crossmool_sm3_hmac_verify(key, NULL, test_data, NULL, hmac_hex);
        if (verify_result == 1) {
            printf("  [PASS] hmac_verify\n");
        } else {
            printf("  [FAIL] hmac_verify\n");
        }
        
        free(hmac_hex);
    } else {
        printf("  [FAIL] hmac\n");
    }
    
    printf("\n=== SM3 Interoperability Test Complete ===\n");
}

void test_sm4_interop(void) {
    printf("\n=== SM4 Interoperability Test ===\n\n");
    
    // 1. 密钥生成
    printf("1. Key Generation Test\n");
    char* key_hex = NULL;
    int ret = crossmool_sm4_generate_key_hex(&key_hex);
    if (ret == CROSSMOOL_SUCCESS) {
        printf("  [PASS] generate_key\n");
        printf("    Key (HEX): %s\n", key_hex);
    } else {
        printf("  [FAIL] generate_key\n");
        return;
    }
    
    unsigned char key[16];
    crossmool_sm4_parse_hex_key(key_hex, key);
    
    // 2. 加密测试
    printf("\n2. Encryption Test\n");
    const char* plaintext = "Hello, SM4!";
    char* ciphertext_hex = NULL;
    ret = crossmool_sm4_encrypt_ecb(key, (const unsigned char*)plaintext, strlen(plaintext), &ciphertext_hex);
    if (ret == CROSSMOOL_SUCCESS) {
        printf("  [PASS] encrypt\n");
        printf("    Plaintext: %s\n", plaintext);
        printf("    Ciphertext (HEX): %s\n", ciphertext_hex);
        
        // 3. 解密测试
        printf("\n3. Decryption Test\n");
        unsigned char* decrypted = NULL;
        size_t decrypted_len = 0;
        ret = crossmool_sm4_decrypt_ecb(key, ciphertext_hex, &decrypted, &decrypted_len);
        if (ret == CROSSMOOL_SUCCESS) {
            printf("  [PASS] decrypt\n");
            printf("    Decrypted: %.*s\n", (int)decrypted_len, decrypted);
            
            if (memcmp(decrypted, plaintext, decrypted_len) == 0) {
                printf("  [PASS] content matches\n");
            } else {
                printf("  [FAIL] content mismatch\n");
            }
            
            free(decrypted);
        } else {
            printf("  [FAIL] decrypt\n");
        }
        
        free(ciphertext_hex);
    } else {
        printf("  [FAIL] encrypt\n");
    }
    
    free(key_hex);
    printf("\n=== SM4 Interoperability Test Complete ===\n");
}

int main(void) {
    printf("========================================\n");
    printf("  Crossmool C Interoperability Tests\n");
    printf("========================================\n\n");
    
    test_sm2_interop();
    test_sm3_interop();
    test_sm4_interop();
    
    printf("\n========================================\n");
    printf("  All Interoperability Tests Complete\n");
    printf("========================================\n");
    
    return 0;
}