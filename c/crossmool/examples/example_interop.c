#include <stdio.h>
#include <string.h>
#include "crossmool.h"

/**
 * 跨语言互通性示例
 * 演示 C 版本与 Java 版本的互通性
 */

int main(void) {
    printf("=== Cross-Language Interoperability Example ===\n\n");
    
    // 1. 生成密钥对
    printf("1. Generate SM2 Key Pair\n");
    crossmool_sm2_keypair_t* keypair = NULL;
    int ret = crossmool_sm2_generate_keypair(&keypair);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        return 1;
    }
    
    ret = crossmool_sm2_keypair_to_hex(keypair);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    ret = crossmool_sm2_keypair_to_base64(keypair);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Private Key (HEX): %s\n", keypair->private_key_hex);
    printf("Public Key (HEX): %s\n", keypair->public_key_hex);
    printf("Private Key (Base64): %s\n", keypair->private_key_base64);
    printf("Public Key (Base64): %s\n\n", keypair->public_key_base64);
    
    // 2. 加密（与 Java 版本互通）
    printf("2. SM2 Encryption (C1C3C2 format)\n");
    const char* message = "Hello from C to Java!";
    char* ciphertext_hex = NULL;
    
    ret = crossmool_sm2_encrypt(message, NULL, keypair->public_key_hex, &ciphertext_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Message: %s\n", message);
    printf("Ciphertext (HEX): %s\n", ciphertext_hex);
    
    // 将密文转换为 Base64（可选，用于网络传输）
    unsigned char* ciphertext_bytes = NULL;
    size_t ciphertext_len = 0;
    crossmool_hex_decode(ciphertext_hex, &ciphertext_bytes, &ciphertext_len);
    
    char* ciphertext_base64 = NULL;
    crossmool_base64_encode(ciphertext_bytes, ciphertext_len, &ciphertext_base64);
    printf("Ciphertext (Base64): %s\n\n", ciphertext_base64);
    
    free(ciphertext_bytes);
    
    // 3. 解密
    printf("3. SM2 Decryption\n");
    char* decrypted = NULL;
    ret = crossmool_sm2_decrypt(ciphertext_hex, keypair->private_key_hex, NULL, &decrypted);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(ciphertext_base64);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Decrypted: %s\n\n", decrypted);
    
    // 4. 签名（与 Java 版本互通）
    printf("4. SM2 Signature\n");
    const char* data = "Sign this message!";
    char* signature_hex = NULL;
    
    ret = crossmool_sm2_sign(data, NULL, keypair->private_key_hex, &signature_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(ciphertext_base64);
        free(decrypted);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Data: %s\n", data);
    printf("Signature (HEX): %s\n", signature_hex);
    
    // 将签名转换为 Base64（可选）
    unsigned char* signature_bytes = NULL;
    size_t signature_len = 0;
    crossmool_hex_decode(signature_hex, &signature_bytes, &signature_len);
    
    char* signature_base64 = NULL;
    crossmool_base64_encode(signature_bytes, signature_len, &signature_base64);
    printf("Signature (Base64): %s\n\n", signature_base64);
    
    free(signature_bytes);
    
    // 5. 验签
    printf("5. SM2 Verification\n");
    int verify_result = crossmool_sm2_verify(data, NULL, signature_hex, keypair->public_key_hex);
    printf("Verify Result: %s\n\n", verify_result == 1 ? "PASS" : "FAIL");
    
    // 6. SM3 杂凑
    printf("6. SM3 Digest\n");
    const char* sm3_input = "Hello, SM3!";
    char* sm3_digest = NULL;
    
    ret = crossmool_sm3_digest_str(sm3_input, NULL, &sm3_digest);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(ciphertext_base64);
        free(decrypted);
        free(signature_hex);
        free(signature_base64);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Input: %s\n", sm3_input);
    printf("Digest (HEX): %s\n\n", sm3_digest);
    
    // 7. HMAC-SM3
    printf("7. HMAC-SM3\n");
    const char* hmac_key = "secret_key";
    const char* hmac_data = "Hello, HMAC!";
    char* hmac_hex = NULL;
    
    ret = crossmool_sm3_hmac_str(hmac_key, NULL, hmac_data, NULL, &hmac_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(ciphertext_base64);
        free(decrypted);
        free(signature_hex);
        free(signature_base64);
        free(sm3_digest);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Key: %s\n", hmac_key);
    printf("Data: %s\n", hmac_data);
    printf("HMAC (HEX): %s\n\n", hmac_hex);
    
    // 8. SM4 加密
    printf("8. SM4 Encryption\n");
    char* sm4_key_hex = NULL;
    ret = crossmool_sm4_generate_key_hex(&sm4_key_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(ciphertext_base64);
        free(decrypted);
        free(signature_hex);
        free(signature_base64);
        free(sm3_digest);
        free(hmac_hex);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    unsigned char sm4_key[16];
    crossmool_sm4_parse_hex_key(sm4_key_hex, sm4_key);
    
    const char* sm4_plaintext = "Hello, SM4!";
    char* sm4_ciphertext = NULL;
    ret = crossmool_sm4_encrypt_ecb(sm4_key, (const unsigned char*)sm4_plaintext, 
                                     strlen(sm4_plaintext), &sm4_ciphertext);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(ciphertext_base64);
        free(decrypted);
        free(signature_hex);
        free(signature_base64);
        free(sm3_digest);
        free(hmac_hex);
        free(sm4_key_hex);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Key (HEX): %s\n", sm4_key_hex);
    printf("Plaintext: %s\n", sm4_plaintext);
    printf("Ciphertext (HEX): %s\n\n", sm4_ciphertext);
    
    // 清理
    free(ciphertext_hex);
    free(ciphertext_base64);
    free(decrypted);
    free(signature_hex);
    free(signature_base64);
    free(sm3_digest);
    free(hmac_hex);
    free(sm4_key_hex);
    free(sm4_ciphertext);
    crossmool_sm2_keypair_free(keypair);
    
    printf("=== Example Complete ===\n");
    printf("\nNote: To test interoperability with Java version:\n");
    printf("1. Copy the generated keys to Java code\n");
    printf("2. Use Java's SM2Util to encrypt/decrypt/sign/verify\n");
    printf("3. Compare results with C version\n");
    
    return 0;
}