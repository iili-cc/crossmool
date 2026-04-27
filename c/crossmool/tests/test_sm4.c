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

// 测试 SM4 密钥生成
void test_key_generation(void) {
    unsigned char key[16];
    
    int ret = crossmool_sm4_generate_key(key);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "generate_key");
    
    char* key_hex = NULL;
    ret = crossmool_hex_encode(key, 16, &key_hex);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "hex_encode");
    
    printf("  Generated Key (HEX): %s\n", key_hex);
    TEST_ASSERT(strlen(key_hex) == 32, "key length is 32");
    
    free(key_hex);
    
    // 测试 HEX 格式生成
    char* key_hex_direct = NULL;
    ret = crossmool_sm4_generate_key_hex(&key_hex_direct);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "generate_key_hex");
    TEST_ASSERT(key_hex_direct != NULL, "key_hex not NULL");
    
    printf("  Generated Key (HEX direct): %s\n", key_hex_direct);
    
    free(key_hex_direct);
}

// 测试 SM4 加密解密
void test_encrypt_decrypt(void) {
    unsigned char key[16];
    crossmool_sm4_generate_key(key);
    
    char* key_hex = NULL;
    crossmool_hex_encode(key, 16, &key_hex);
    
    const char* plaintext = "Hello, SM4 Encryption!";
    char* ciphertext_hex = NULL;
    
    int ret = crossmool_sm4_encrypt_ecb(key, (const unsigned char*)plaintext, strlen(plaintext), &ciphertext_hex);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "encrypt_ecb");
    TEST_ASSERT(ciphertext_hex != NULL, "ciphertext not NULL");
    
    printf("  Plaintext: %s\n", plaintext);
    printf("  Ciphertext (HEX): %s\n", ciphertext_hex);
    
    // 解密
    unsigned char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    ret = crossmool_sm4_decrypt_ecb(key, ciphertext_hex, &decrypted, &decrypted_len);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "decrypt_ecb");
    TEST_ASSERT(decrypted != NULL, "decrypted not NULL");
    TEST_ASSERT(decrypted_len == strlen(plaintext), "decrypted length matches");
    TEST_ASSERT(memcmp(decrypted, plaintext, decrypted_len) == 0, "decrypted content matches");
    
    printf("  Decrypted: %.*s\n", (int)decrypted_len, decrypted);
    
    free(ciphertext_hex);
    free(decrypted);
    free(key_hex);
}

// 测试 SM4 解析 HEX 密钥
void test_parse_hex_key(void) {
    const char* hex_key = "0123456789abcdef0123456789abcdef";
    unsigned char key[16];
    
    int ret = crossmool_sm4_parse_hex_key(hex_key, key);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "parse_hex_key");
    
    // 验证密钥内容
    TEST_ASSERT(key[0] == 0x01, "key[0] == 0x01");
    TEST_ASSERT(key[15] == 0xef, "key[15] == 0xef");
    
    printf("  HEX Key: %s\n", hex_key);
    printf("  Parsed Key: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
}

int main(void) {
    printf("=== SM4 Unit Tests ===\n\n");
    passed = 0;
    
    printf("\n--- Test Key Generation ---\n");
    test_key_generation();
    
    printf("\n--- Test Parse HEX Key ---\n");
    test_parse_hex_key();
    
    printf("\n--- Test Encrypt/Decrypt ---\n");
    test_encrypt_decrypt();
    
    printf("\n=== Tests Complete ===\n");
    return 0;
}