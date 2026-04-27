#include <stdio.h>
#include <string.h>
#include "crossmool.h"

#define TEST_ASSERT(expr, msg) do { \
    if (!(expr)) { \
        printf("[FAIL] %s: %s\n", __func__, msg); \
        passed--; \
    } else { \
        printf("[PASS] %s\n", __func__); \
    } \
} while(0)

static int passed = 0;

// 测试密钥生成
void test_keypair_generation(void) {
    crossmool_sm2_keypair_t* keypair = NULL;
    
    int ret = crossmool_sm2_generate_keypair(&keypair);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS && keypair != NULL, "generate_keypair");
    
    TEST_ASSERT(keypair->private_key != NULL, "private_key not NULL");
    TEST_ASSERT(keypair->public_key != NULL, "public_key not NULL");
    
    ret = crossmool_sm2_keypair_to_hex(keypair);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "keypair_to_hex");
    TEST_ASSERT(keypair->private_key_hex != NULL, "private_key_hex not NULL");
    TEST_ASSERT(keypair->public_key_hex != NULL, "public_key_hex not NULL");
    
    ret = crossmool_sm2_keypair_to_base64(keypair);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "keypair_to_base64");
    TEST_ASSERT(keypair->private_key_base64 != NULL, "private_key_base64 not NULL");
    TEST_ASSERT(keypair->public_key_base64 != NULL, "public_key_base64 not NULL");
    
    printf("  Private Key (HEX): %s\n", keypair->private_key_hex);
    printf("  Public Key (HEX): %s\n", keypair->public_key_hex);
    
    crossmool_sm2_keypair_free(keypair);
}

// 测试加密解密
void test_encrypt_decrypt(void) {
    crossmool_sm2_keypair_t* keypair = NULL;
    
    crossmool_sm2_generate_keypair(&keypair);
    crossmool_sm2_keypair_to_hex(keypair);
    
    const char* plaintext = "Hello, SM2 Encryption!";
    char* ciphertext_hex = NULL;
    
    int ret = crossmool_sm2_encrypt(plaintext, NULL, keypair->public_key_hex, &ciphertext_hex);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "encrypt");
    TEST_ASSERT(ciphertext_hex != NULL, "ciphertext not NULL");
    
    printf("  Ciphertext (HEX): %s\n", ciphertext_hex);
    
    char* decrypted = NULL;
    ret = crossmool_sm2_decrypt(ciphertext_hex, keypair->private_key_hex, NULL, &decrypted);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "decrypt");
    TEST_ASSERT(decrypted != NULL, "decrypted not NULL");
    TEST_ASSERT(strcmp(decrypted, plaintext) == 0, "plaintext matches");
    
    printf("  Plaintext: %s\n", plaintext);
    printf("  Decrypted: %s\n", decrypted);
    
    free(ciphertext_hex);
    free(decrypted);
    crossmool_sm2_keypair_free(keypair);
}

// 测试签名验签
void test_sign_verify(void) {
    crossmool_sm2_keypair_t* keypair = NULL;
    
    crossmool_sm2_generate_keypair(&keypair);
    crossmool_sm2_keypair_to_hex(keypair);
    
    const char* data = "Hello, SM2 Signature!";
    char* signature_hex = NULL;
    
    int ret = crossmool_sm2_sign(data, NULL, keypair->private_key_hex, &signature_hex);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "sign");
    TEST_ASSERT(signature_hex != NULL, "signature not NULL");
    
    printf("  Signature (HEX): %s\n", signature_hex);
    
    int verify_result = crossmool_sm2_verify(data, NULL, signature_hex, keypair->public_key_hex);
    TEST_ASSERT(verify_result == 1, "verify passed");
    
    // 测试错误签名
    const char* tampered_data = "Tampered data!";
    verify_result = crossmool_sm2_verify(tampered_data, NULL, signature_hex, keypair->public_key_hex);
    TEST_ASSERT(verify_result == 0, "verify failed for tampered data");
    
    free(signature_hex);
    crossmool_sm2_keypair_free(keypair);
}

// 测试加密签名组合
void test_encrypt_sign_combo(void) {
    crossmool_sm2_keypair_t* enc_keypair = NULL;
    crossmool_sm2_keypair_t* sign_keypair = NULL;
    
    crossmool_sm2_generate_keypair(&enc_keypair);
    crossmool_sm2_generate_keypair(&sign_keypair);
    crossmool_sm2_keypair_to_hex(enc_keypair);
    crossmool_sm2_keypair_to_hex(sign_keypair);
    
    const char* content = "Hello, Encrypt and Sign!";
    crossmool_sm2_cipher_sig_pair_t* pair = NULL;
    
    int ret = crossmool_sm2_encrypt_sign(content, NULL, enc_keypair->public_key_hex, 
                                          sign_keypair->private_key_hex, &pair);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "encrypt_sign");
    TEST_ASSERT(pair != NULL, "pair not NULL");
    
    printf("  Ciphertext: %s\n", pair->ciphertext_hex);
    printf("  Signature: %s\n", pair->signature_hex);
    
    char* result = NULL;
    ret = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex,
                                        sign_keypair->public_key_hex, enc_keypair->private_key_hex,
                                        NULL, &result);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "verify_decrypt");
    TEST_ASSERT(result != NULL, "result not NULL");
    TEST_ASSERT(strcmp(result, content) == 0, "content matches");
    
    printf("  Original: %s\n", content);
    printf("  Result: %s\n", result);
    
    free(result);
    crossmool_sm2_cipher_sig_pair_free(pair);
    crossmool_sm2_keypair_free(enc_keypair);
    crossmool_sm2_keypair_free(sign_keypair);
}

int main(void) {
    printf("=== SM2 Unit Tests ===\n\n");
    passed = 0;
    
    printf("\n--- Test Key Pair Generation ---\n");
    test_keypair_generation();
    
    printf("\n--- Test Encrypt/Decrypt ---\n");
    test_encrypt_decrypt();
    
    printf("\n--- Test Sign/Verify ---\n");
    test_sign_verify();
    
    printf("\n--- Test Encrypt/Sign Combo ---\n");
    test_encrypt_sign_combo();
    
    printf("\n=== Tests Complete ===\n");
    return 0;
}