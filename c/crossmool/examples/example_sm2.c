#include <stdio.h>
#include <string.h>
#include "crossmool.h"

int main(void) {
    printf("=== SM2 Example ===\n\n");
    
    // 1. 生成密钥对
    printf("1. Generate Key Pair\n");
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
    
    printf("Private Key (HEX): %s\n", keypair->private_key_hex);
    printf("Public Key (HEX): %s\n\n", keypair->public_key_hex);
    
    // 2. 加密
    printf("2. Encryption\n");
    const char* message = "Hello, SM2 Encryption!";
    char* ciphertext_hex = NULL;
    
    ret = crossmool_sm2_encrypt(message, NULL, keypair->public_key_hex, &ciphertext_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Original: %s\n", message);
    printf("Ciphertext (HEX): %s\n\n", ciphertext_hex);
    
    // 3. 解密
    printf("3. Decryption\n");
    char* decrypted = NULL;
    ret = crossmool_sm2_decrypt(ciphertext_hex, keypair->private_key_hex, NULL, &decrypted);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Decrypted: %s\n\n", decrypted);
    
    // 4. 签名
    printf("4. Signature\n");
    const char* data = "Hello, SM2 Signature!";
    char* signature_hex = NULL;
    
    ret = crossmool_sm2_sign(data, NULL, keypair->private_key_hex, &signature_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(decrypted);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Data: %s\n", data);
    printf("Signature (HEX): %s\n\n", signature_hex);
    
    // 5. 验签
    printf("5. Verification\n");
    int verify_result = crossmool_sm2_verify(data, NULL, signature_hex, keypair->public_key_hex);
    printf("Data: %s\n", data);
    printf("Verify Result: %s\n\n", verify_result == 1 ? "PASS" : "FAIL");
    
    // 6. 加密并签名
    printf("6. Encrypt and Sign\n");
    const char* content = "Hello, Encrypt and Sign!";
    crossmool_sm2_cipher_sig_pair_t* pair = NULL;
    
    ret = crossmool_sm2_encrypt_sign(content, NULL, keypair->public_key_hex, 
                                      keypair->private_key_hex, &pair);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(decrypted);
        free(signature_hex);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Content: %s\n", content);
    printf("Ciphertext: %s\n", pair->ciphertext_hex);
    printf("Signature: %s\n\n", pair->signature_hex);
    
    // 7. 验签并解密
    printf("7. Verify and Decrypt\n");
    char* result = NULL;
    ret = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex,
                                        keypair->public_key_hex, keypair->private_key_hex,
                                        NULL, &result);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("Error: %s\n", crossmool_error_string(ret));
        free(ciphertext_hex);
        free(decrypted);
        free(signature_hex);
        crossmool_sm2_cipher_sig_pair_free(pair);
        crossmool_sm2_keypair_free(keypair);
        return 1;
    }
    
    printf("Result: %s\n\n", result);
    
    // 清理
    free(ciphertext_hex);
    free(decrypted);
    free(signature_hex);
    free(result);
    crossmool_sm2_cipher_sig_pair_free(pair);
    crossmool_sm2_keypair_free(keypair);
    
    printf("=== Example Complete ===\n");
    return 0;
}