#include <stdio.h>
#include <string.h>
#include "crossmool.h"

int main(void) {
    printf("=== SM2 Unit Tests ===\n\n");
    
    /* Test 1: Key Pair Generation */
    printf("--- Test Key Pair Generation ---\n");
    crossmool_sm2_keypair_t* keypair = NULL;
    int ret = crossmool_sm2_generate_keypair(&keypair);
    printf("  generate_keypair returned: %d\n", ret);
    
    if (ret != CROSSMOOL_SUCCESS || keypair == NULL) {
        printf("  [FAIL] generate_keypair: %s\n", crossmool_error_string(ret));
        return 1;
    }
    printf("  [PASS] generate_keypair\n");
    
    printf("  private_key: %s\n", keypair->private_key ? keypair->private_key : "(null)");
    printf("  public_key: %s\n", keypair->public_key ? keypair->public_key : "(null)");
    printf("  private_key_hex: %s\n", keypair->private_key_hex ? keypair->private_key_hex : "(null)");
    printf("  public_key_hex: %s\n", keypair->public_key_hex ? keypair->public_key_hex : "(null)");
    
    crossmool_sm2_keypair_free(keypair);
    keypair = NULL;
    
    /* Test 2: Encrypt/Decrypt */
    printf("\n--- Test Encrypt/Decrypt ---\n");
    crossmool_sm2_keypair_t* kp2 = NULL;
    ret = crossmool_sm2_generate_keypair(&kp2);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("  [FAIL] generate_keypair for encrypt test\n");
        return 1;
    }
    
    const char* plaintext = "Hello, SM2 Encryption!";
    char* ciphertext_hex = NULL;
    
    ret = crossmool_sm2_encrypt(plaintext, NULL, kp2->public_key_hex, &ciphertext_hex);
    if (ret == CROSSMOOL_SUCCESS && ciphertext_hex != NULL) {
        printf("  [PASS] encrypt\n");
        
        char* decrypted = NULL;
        ret = crossmool_sm2_decrypt(ciphertext_hex, kp2->private_key_hex, NULL, &decrypted);
        if (ret == CROSSMOOL_SUCCESS && decrypted != NULL && strcmp(decrypted, plaintext) == 0) {
            printf("  [PASS] decrypt - plaintext matches\n");
        } else {
            printf("  [FAIL] decrypt (ret=%d, decrypted=%s)\n", ret, decrypted ? decrypted : "(null)");
        }
        free(decrypted);
        free(ciphertext_hex);
    } else {
        printf("  [FAIL] encrypt (ret=%d)\n", ret);
    }
    
    crossmool_sm2_keypair_free(kp2);
    kp2 = NULL;
    
    /* Test 3: Sign/Verify */
    printf("\n--- Test Sign/Verify ---\n");
    crossmool_sm2_keypair_t* kp3 = NULL;
    ret = crossmool_sm2_generate_keypair(&kp3);
    if (ret != CROSSMOOL_SUCCESS) {
        printf("  [FAIL] generate_keypair for sign test\n");
        return 1;
    }
    
    const char* data = "Hello, SM2 Signature!";
    char* signature_hex = NULL;
    
    ret = crossmool_sm2_sign(data, NULL, kp3->private_key_hex, &signature_hex);
    if (ret == CROSSMOOL_SUCCESS && signature_hex != NULL) {
        printf("  [PASS] sign\n");
        
        int verify_result = crossmool_sm2_verify(data, NULL, signature_hex, kp3->public_key_hex);
        if (verify_result == 1) {
            printf("  [PASS] verify\n");
        } else {
            printf("  [FAIL] verify (result=%d)\n", verify_result);
        }
        
        /* Test tampered data */
        int tampered_result = crossmool_sm2_verify("Tampered data!", NULL, signature_hex, kp3->public_key_hex);
        if (tampered_result == 0) {
            printf("  [PASS] verify correctly rejected tampered data\n");
        } else {
            printf("  [FAIL] verify should reject tampered data (result=%d)\n", tampered_result);
        }
        
        free(signature_hex);
    } else {
        printf("  [FAIL] sign (ret=%d)\n", ret);
    }
    
    crossmool_sm2_keypair_free(kp3);
    kp3 = NULL;
    
    /* Test 4: Encrypt+Sign Combo */
    printf("\n--- Test Encrypt/Sign Combo ---\n");
    crossmool_sm2_keypair_t* enc_kp = NULL;
    crossmool_sm2_keypair_t* sign_kp = NULL;
    crossmool_sm2_generate_keypair(&enc_kp);
    crossmool_sm2_generate_keypair(&sign_kp);
    
    const char* content = "Hello, Encrypt and Sign!";
    crossmool_sm2_cipher_sig_pair_t* pair = NULL;
    
    ret = crossmool_sm2_encrypt_sign(content, NULL, enc_kp->public_key_hex, 
                                      sign_kp->private_key_hex, &pair);
    if (ret == CROSSMOOL_SUCCESS && pair != NULL) {
        printf("  [PASS] encrypt_sign\n");
        
        char* result = NULL;
        ret = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex,
                                            sign_kp->public_key_hex, enc_kp->private_key_hex,
                                            NULL, &result);
        if (ret == CROSSMOOL_SUCCESS && result != NULL && strcmp(result, content) == 0) {
            printf("  [PASS] verify_decrypt - content matches\n");
        } else {
            printf("  [FAIL] verify_decrypt (ret=%d)\n", ret);
        }
        if (result) free(result);
        crossmool_sm2_cipher_sig_pair_free(pair);
    } else {
        printf("  [FAIL] encrypt_sign (ret=%d)\n", ret);
    }
    
    crossmool_sm2_keypair_free(enc_kp);
    crossmool_sm2_keypair_free(sign_kp);
    
    printf("\n=== Tests Complete ===\n");
    return 0;
}
