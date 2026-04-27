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

// 测试 SM3 杂凑计算
void test_sm3_digest(void) {
    const char* input = "Hello, SM3!";
    char* digest_hex = NULL;
    
    int ret = crossmool_sm3_digest_str(input, NULL, &digest_hex);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "digest_str");
    TEST_ASSERT(digest_hex != NULL, "digest_hex not NULL");
    
    printf("  Input: %s\n", input);
    printf("  Digest (HEX): %s\n", digest_hex);
    
    // 验证长度（64 个十六进制字符 = 32 字节）
    TEST_ASSERT(strlen(digest_hex) == 64, "digest length is 64");
    
    free(digest_hex);
}

// 测试 SM3 杂凑（字节数组）
void test_sm3_digest_bytes(void) {
    const unsigned char data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    unsigned char digest[32];
    
    int ret = crossmool_sm3_digest(data, sizeof(data), digest);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "digest");
    
    char* digest_hex = NULL;
    ret = crossmool_hex_encode(digest, 32, &digest_hex);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "hex_encode");
    
    printf("  Data: 01 02 03 04 05\n");
    printf("  Digest (HEX): %s\n", digest_hex);
    
    free(digest_hex);
}

// 测试 HMAC-SM3
void test_hmac_sm3(void) {
    const char* key = "secret_key";
    const char* data = "Hello, HMAC-SM3!";
    char* hmac_hex = NULL;
    
    int ret = crossmool_sm3_hmac_str(key, NULL, data, NULL, &hmac_hex);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "hmac_str");
    TEST_ASSERT(hmac_hex != NULL, "hmac_hex not NULL");
    
    printf("  Key: %s\n", key);
    printf("  Data: %s\n", data);
    printf("  HMAC (HEX): %s\n", hmac_hex);
    
    // 验证长度
    TEST_ASSERT(strlen(hmac_hex) == 64, "hmac length is 64");
    
    // 测试验证
    int verify_result = crossmool_sm3_hmac_verify(key, NULL, data, NULL, hmac_hex);
    TEST_ASSERT(verify_result == 1, "hmac_verify passed");
    
    // 测试错误密钥
    verify_result = crossmool_sm3_hmac_verify("wrong_key", NULL, data, NULL, hmac_hex);
    TEST_ASSERT(verify_result == 0, "hmac_verify failed for wrong key");
    
    free(hmac_hex);
}

// 测试 HMAC-SM3（字节数组）
void test_hmac_sm3_bytes(void) {
    const unsigned char key[] = {0x01, 0x02, 0x03, 0x04};
    const unsigned char data[] = {0x11, 0x22, 0x33, 0x44};
    unsigned char hmac[32];
    
    int ret = crossmool_sm3_hmac(key, sizeof(key), data, sizeof(data), hmac);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "hmac");
    
    char* hmac_hex = NULL;
    ret = crossmool_hex_encode(hmac, 32, &hmac_hex);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "hex_encode");
    
    printf("  Key: 01 02 03 04\n");
    printf("  Data: 11 22 33 44\n");
    printf("  HMAC (HEX): %s\n", hmac_hex);
    
    free(hmac_hex);
}

int main(void) {
    printf("=== SM3 Unit Tests ===\n\n");
    passed = 0;
    
    printf("\n--- Test SM3 Digest ---\n");
    test_sm3_digest();
    
    printf("\n--- Test SM3 Digest (Bytes) ---\n");
    test_sm3_digest_bytes();
    
    printf("\n--- Test HMAC-SM3 ---\n");
    test_hmac_sm3();
    
    printf("\n--- Test HMAC-SM3 (Bytes) ---\n");
    test_hmac_sm3_bytes();
    
    printf("\n=== Tests Complete ===\n");
    return 0;
}