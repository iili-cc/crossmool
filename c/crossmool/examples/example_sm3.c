#include <stdio.h>
#include <string.h>
#include "crossmool.h"

int main(void) {
    printf("=== SM3 Example ===\n\n");
    
    // 1. 杂凑计算（字符串）
    printf("1. Digest (String)\n");
    const char* input = "Hello, SM3!";
    char* digest_hex = NULL;
    
    int ret = crossmool_sm3_digest_str(input, NULL, &digest_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        return 1;
    }
    
    printf("Input: %s\n", input);
    printf("Digest (HEX): %s\n\n", digest_hex);
    
    // 2. 杂凑计算（字节数组）
    printf("2. Digest (Bytes)\n");
    const unsigned char data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    unsigned char digest[32];
    
    ret = crossmool_sm3_digest(data, sizeof(data), digest);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(digest_hex);
        return 1;
    }
    
    char* digest_hex2 = NULL;
    crossmool_hex_encode(digest, 32, &digest_hex2);
    
    printf("Input: ");
    for (size_t i = 0; i < sizeof(data); i++) {
        printf("%02x ", data[i]);
    }
    printf("\nDigest (HEX): %s\n\n", digest_hex2);
    
    // 3. HMAC-SM3
    printf("3. HMAC-SM3\n");
    const char* key = "secret_key";
    const char* message = "Hello, HMAC-SM3!";
    char* hmac_hex = NULL;
    
    ret = crossmool_sm3_hmac_str(key, NULL, message, NULL, &hmac_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(digest_hex);
        free(digest_hex2);
        return 1;
    }
    
    printf("Key: %s\n", key);
    printf("Message: %s\n", message);
    printf("HMAC (HEX): %s\n\n", hmac_hex);
    
    // 4. HMAC 验证
    printf("4. HMAC Verification\n");
    int verify_result = crossmool_sm3_hmac_verify(key, NULL, message, NULL, hmac_hex);
    printf("Verify Result: %s\n\n", verify_result == 1 ? "PASS" : "FAIL");
    
    // 5. 错误密钥验证
    printf("5. HMAC Verification (Wrong Key)\n");
    verify_result = crossmool_sm3_hmac_verify("wrong_key", NULL, message, NULL, hmac_hex);
    printf("Verify Result: %s\n\n", verify_result == 1 ? "PASS" : "FAIL (expected)");
    
    // 清理
    free(digest_hex);
    free(digest_hex2);
    free(hmac_hex);
    
    printf("=== Example Complete ===\n");
    return 0;
}