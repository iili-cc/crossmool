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

// 测试 HEX 编解码
void test_hex_codec(void) {
    const unsigned char data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    char* hex_str = NULL;
    int ret = crossmool_hex_encode(data, sizeof(data), &hex_str);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "hex_encode");
    TEST_ASSERT(hex_str != NULL, "hex_str not NULL");
    
    printf("  Original: 01 23 45 67 89 AB CD EF\n");
    printf("  Encoded: %s\n", hex_str);
    TEST_ASSERT(strcmp(hex_str, "0123456789abcdef") == 0, "hex content matches");
    
    // 解码
    unsigned char* decoded = NULL;
    size_t decoded_len = 0;
    ret = crossmool_hex_decode(hex_str, &decoded, &decoded_len);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "hex_decode");
    TEST_ASSERT(decoded_len == sizeof(data), "decoded length matches");
    TEST_ASSERT(memcmp(decoded, data, decoded_len) == 0, "decoded content matches");
    
    // 格式检测
    TEST_ASSERT(crossmool_is_hex_string(hex_str) == 1, "is_hex_string true");
    TEST_ASSERT(crossmool_is_hex_string("01234") == 0, "is_hex_string false (odd length)");
    TEST_ASSERT(crossmool_is_hex_string("XYZ") == 0, "is_hex_string false (invalid chars)");
    
    free(hex_str);
    free(decoded);
}

// 测试 Base64 编解码
void test_base64_codec(void) {
    const unsigned char data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    
    char* base64_str = NULL;
    int ret = crossmool_base64_encode(data, sizeof(data), &base64_str);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "base64_encode");
    TEST_ASSERT(base64_str != NULL, "base64_str not NULL");
    
    printf("  Original: 01 23 45 67 89 AB CD EF\n");
    printf("  Encoded: %s\n", base64_str);
    
    // 解码
    unsigned char* decoded = NULL;
    size_t decoded_len = 0;
    ret = crossmool_base64_decode(base64_str, &decoded, &decoded_len);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "base64_decode");
    TEST_ASSERT(decoded_len == sizeof(data), "decoded length matches");
    TEST_ASSERT(memcmp(decoded, data, decoded_len) == 0, "decoded content matches");
    
    // 格式检测
    TEST_ASSERT(crossmool_is_base64_string(base64_str) == 1, "is_base64_string true");
    TEST_ASSERT(crossmool_is_base64_string("hello") == 0, "is_base64_string false (invalid)");
    
    free(base64_str);
    free(decoded);
}

// 测试字符串转换
void test_string_conversion(void) {
    const char* str = "Hello, World!";
    
    unsigned char* data = NULL;
    size_t data_len = 0;
    
    // 字符串转字节
    int ret = crossmool_string_to_bytes(str, NULL, &data, &data_len);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "string_to_bytes");
    TEST_ASSERT(data_len == strlen(str), "data length matches");
    
    printf("  Original: %s\n", str);
    
    // 字节转字符串
    char* result = NULL;
    ret = crossmool_bytes_to_string(data, data_len, NULL, &result);
    TEST_ASSERT(ret == CROSSMOOL_SUCCESS, "bytes_to_string");
    TEST_ASSERT(strcmp(result, str) == 0, "result matches original");
    
    printf("  Converted: %s\n", result);
    
    free(data);
    free(result);
}

// 测试错误处理
void test_error_handling(void) {
    const char* error_msg = crossmool_error_string(CROSSMOOL_SUCCESS);
    printf("  Success message: %s\n", error_msg);
    
    error_msg = crossmool_error_string(CROSSMOOL_ERR_INVALID_PARAM);
    printf("  Error message: %s\n", error_msg);
    
    const char* version = crossmool_version();
    printf("  Version: %s\n", version);
    
    TEST_ASSERT(version != NULL, "version not NULL");
}

int main(void) {
    printf("=== Utility Unit Tests ===\n\n");
    passed = 0;
    
    printf("\n--- Test HEX Codec ---\n");
    test_hex_codec();
    
    printf("\n--- Test Base64 Codec ---\n");
    test_base64_codec();
    
    printf("\n--- Test String Conversion ---\n");
    test_string_conversion();
    
    printf("\n--- Test Error Handling ---\n");
    test_error_handling();
    
    printf("\n=== Tests Complete ===\n");
    return 0;
}