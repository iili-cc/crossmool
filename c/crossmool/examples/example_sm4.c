#include <stdio.h>
#include <string.h>
#include "crossmool.h"

int main(void) {
    printf("=== SM4 GCM Example ===\n\n");
    
    // 1. 生成密钥
    printf("1. Generate Key\n");
    char* key_hex = NULL;
    int ret = crossmool_sm4_generate_key_hex(&key_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        return 1;
    }
    
    printf("Key (HEX): %s\n\n", key_hex);
    
    unsigned char key[16];
    ret = crossmool_sm4_parse_hex_key(key_hex, key);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(key_hex);
        return 1;
    }
    
    // 2. GCM 加密
    printf("2. GCM Encryption\n");
    const char* plaintext = "Hello, SM4 GCM Encryption!";
    char* ciphertext_base64 = NULL;
    
    ret = crossmool_sm4_encrypt_gcm(key, (const unsigned char*)plaintext, strlen(plaintext), &ciphertext_base64);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(key_hex);
        return 1;
    }
    
    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext (Base64): %s\n\n", ciphertext_base64);
    
    // 3. GCM 解密
    printf("3. GCM Decryption\n");
    unsigned char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    ret = crossmool_sm4_decrypt_gcm(key, ciphertext_base64, &decrypted, &decrypted_len);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(key_hex);
        free(ciphertext_base64);
        return 1;
    }
    
    printf("Decrypted: %.*s\n\n", (int)decrypted_len, decrypted);
    
    // 4. 使用自定义密钥
    printf("4. Custom Key GCM Encryption\n");
    const char* custom_key_hex = "0123456789abcdef0123456789abcdef";
    const char* custom_plaintext = "Custom key GCM test";
    
    unsigned char custom_key[16];
    ret = crossmool_sm4_parse_hex_key(custom_key_hex, custom_key);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(key_hex);
        free(ciphertext_base64);
        free(decrypted);
        return 1;
    }
    
    char* custom_ciphertext_base64 = NULL;
    ret = crossmool_sm4_encrypt_gcm(custom_key, (const unsigned char*)custom_plaintext, 
                                     strlen(custom_plaintext), &custom_ciphertext_base64);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(key_hex);
        free(ciphertext_base64);
        free(decrypted);
        return 1;
    }
    
    printf("Key (HEX): %s\n", custom_key_hex);
    printf("Plaintext: %s\n", custom_plaintext);
    printf("Ciphertext (Base64): %s\n\n", custom_ciphertext_base64);
    
    // 5. 解密验证
    printf("5. Custom Key GCM Decryption\n");
    unsigned char* custom_decrypted = NULL;
    size_t custom_decrypted_len = 0;
    
    ret = crossmool_sm4_decrypt_gcm(custom_key, custom_ciphertext_base64, 
                                     &custom_decrypted, &custom_decrypted_len);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(key_hex);
        free(ciphertext_base64);
        free(decrypted);
        free(custom_ciphertext_base64);
        return 1;
    }
    
    printf("Decrypted: %.*s\n\n", (int)custom_decrypted_len, custom_decrypted);
    
    // 清理
    free(key_hex);
    free(ciphertext_base64);
    free(decrypted);
    free(custom_ciphertext_base64);
    free(custom_decrypted);
    
    printf("=== Example Complete ===\n");
    return 0;
}
