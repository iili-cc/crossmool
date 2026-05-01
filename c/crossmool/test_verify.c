#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

int main(void) {
    FILE* fp = fopen("test_result.txt", "w");
    if (!fp) {
        printf("Cannot open output file\n");
        return 1;
    }
    
    fprintf(fp, "=== SM2 Sign/Verify Test with USER_ID ===\n\n");
    printf("=== SM2 Sign/Verify Test with USER_ID ===\n\n");
    
    /* Generate key pair */
    crossmool_sm2_keypair_t* kp = NULL;
    int ret = crossmool_sm2_generate_keypair(&kp);
    if (ret != CROSSMOOL_SUCCESS) {
        fprintf(fp, "Key generation failed: %d\n", ret);
        printf("Key generation failed: %d\n", ret);
        fclose(fp);
        return 1;
    }
    
    fprintf(fp, "Generated key pair:\n");
    fprintf(fp, "  Private: %s\n", kp->private_key_hex);
    fprintf(fp, "  Public:  %s\n\n", kp->public_key_hex);
    printf("Generated key pair:\n");
    printf("  Private: %s\n", kp->private_key_hex);
    printf("  Public:  %s\n\n", kp->public_key_hex);
    
    /* Test data */
    const char* content = "Hello, SM2!";
    char* signature = NULL;
    
    /* Sign */
    ret = crossmool_sm2_sign(content, NULL, kp->private_key_hex, &signature);
    if (ret != CROSSMOOL_SUCCESS) {
        fprintf(fp, "Sign failed: %d\n", ret);
        printf("Sign failed: %d\n", ret);
        crossmool_sm2_keypair_free(kp);
        fclose(fp);
        return 1;
    }
    
    fprintf(fp, "Content: %s\n", content);
    fprintf(fp, "Signature (hex): %s\n\n", signature);
    printf("Content: %s\n", content);
    printf("Signature (hex): %s\n\n", signature);
    
    /* Verify */
    int verify_result = crossmool_sm2_verify(content, NULL, signature, kp->public_key_hex);
    if (verify_result == 1) {
        fprintf(fp, "[PASS] Verification succeeded!\n");
        printf("[PASS] Verification succeeded!\n");
    } else {
        fprintf(fp, "[FAIL] Verification failed: %d\n", verify_result);
        printf("[FAIL] Verification failed: %d\n", verify_result);
    }
    
    /* Verify with wrong content */
    int wrong_verify = crossmool_sm2_verify("Wrong content", NULL, signature, kp->public_key_hex);
    if (wrong_verify == 0) {
        fprintf(fp, "[PASS] Correctly rejected tampered content!\n");
        printf("[PASS] Correctly rejected tampered content!\n");
    } else {
        fprintf(fp, "[FAIL] Should reject tampered content: %d\n", wrong_verify);
        printf("[FAIL] Should reject tampered content: %d\n", wrong_verify);
    }
    
    free(signature);
    crossmool_sm2_keypair_free(kp);
    
    fprintf(fp, "\n=== Test Complete ===\n");
    printf("\n=== Test Complete ===\n");
    
    fclose(fp);
    return 0;
}