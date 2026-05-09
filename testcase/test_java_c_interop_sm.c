/**
 * Java-C SM2/SM3/SM4 Interoperability Test Program
 * 
 * Test scenarios:
 * 1. Java Encrypt -> C Decrypt
 * 2. C Encrypt -> Java Decrypt
 * 3. Java Sign -> C Verify
 * 4. C Sign -> Java Verify
 * 5. Java SM3 -> C Verify
 * 6. C SM3 -> Java Verify
 * 7. Java SM4 Encrypt -> C Decrypt
 * 8. C SM4 Encrypt -> Java Decrypt
 * 9. Java HMAC-SM3 -> C Verify
 * 10. C HMAC-SM3 -> Java Verify
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool_sm2.h"
#include "crossmool_sm3.h"
#include "crossmool_sm4.h"

#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

/* ====================================================
 * 测试数据
 * ==================================================== */
static const char* TEST_MESSAGE = "Hello, Cross-Language Interop Test!";
static const char* TEST_HMAC_KEY = "0123456789abcdef0123456789abcdef";  /* 32 字节 HEX */

/* ====================================================
 * Test Data
 * ==================================================== */
static void print_section(const char* title) {
    printf("\n");
    printf("============================================================\n");
    printf(" %s\n", title);
    printf("============================================================\n");
}

static void print_result(const char* test_name, int success, const char* details) {
    printf("[%s] %s: %s\n", 
           success ? "PASS" : "FAIL", 
           test_name, 
           details ? details : "");
}

/* ====================================================
 * Helper Functions
 * ==================================================== */

/* Test 1: Java Encrypt -> C Decrypt */
int test_sm2_java_encrypt_c_decrypt(const char* java_ciphertext_hex, 
                                     const char* c_private_key_hex) {
    print_section("SM2 Test: Java Encrypt -> C Decrypt");
    
    char* decrypted = NULL;
    int ret = crossmool_sm2_decrypt(java_ciphertext_hex, c_private_key_hex, "UTF-8", &decrypted);
    
    if (ret == CROSSMOOL_SUCCESS && decrypted != NULL) {
        printf("  C decrypted: %s\n", decrypted);
        int match = (strcmp(decrypted, TEST_MESSAGE) == 0);
        free(decrypted);
        print_result("Java Encrypt -> C Decrypt", match, match ? "Decrypted text matches original" : "Decrypted text mismatch");
        return match ? 0 : -1;
    }
    
    print_result("Java Encrypt -> C Decrypt", 0, "Decryption failed");
    return -1;
}

/* Test 2: C Encrypt -> Java Decrypt (output ciphertext for Java verification) */
int test_sm2_c_encrypt_java_decrypt(const char* c_public_key_hex) {
    print_section("SM2 Test: C Encrypt -> Java Decrypt");
    
    char* ciphertext_hex = NULL;
    int ret = crossmool_sm2_encrypt(TEST_MESSAGE, "UTF-8", c_public_key_hex, &ciphertext_hex);
    
    if (ret == CROSSMOOL_SUCCESS && ciphertext_hex != NULL) {
        printf("  C ciphertext (hex): %s\n", ciphertext_hex);
        printf("  [Java should decrypt this and verify it equals: %s]\n", TEST_MESSAGE);
        print_result("C Encrypt -> Java Decrypt", 1, "Ciphertext generated, please verify with Java");
        free(ciphertext_hex);
        return 0;
    }
    
    print_result("C Encrypt -> Java Decrypt", 0, "Encryption failed");
    return -1;
}

/* Test 3: Java Sign -> C Verify */
int test_sm2_java_sign_c_verify(const char* java_signature_hex,
                                 const char* c_public_key_hex) {
    print_section("SM2 Test: Java Sign -> C Verify");
    
    int ret = crossmool_sm2_verify(TEST_MESSAGE, "UTF-8", java_signature_hex, c_public_key_hex);
    
    if (ret == 1) {
        print_result("Java Sign -> C Verify", 1, "Signature verified successfully");
        return 0;
    }
    
    print_result("Java Sign -> C Verify", 0, ret == 0 ? "Signature verification failed" : "Error");
    return -1;
}

/* Test 4: C Sign -> Java Verify (output signature for Java verification) */
int test_sm2_c_sign_java_verify(const char* c_private_key_hex) {
    print_section("SM2 Test: C Sign -> Java Verify");
    
    char* signature_hex = NULL;
    int ret = crossmool_sm2_sign(TEST_MESSAGE, "UTF-8", c_private_key_hex, &signature_hex);
    
    if (ret == CROSSMOOL_SUCCESS && signature_hex != NULL) {
        printf("  C signature (hex): %s\n", signature_hex);
        printf("  [Java should verify this signature against: %s]\n", TEST_MESSAGE);
        print_result("C Sign -> Java Verify", 1, "Signature generated, please verify with Java");
        free(signature_hex);
        return 0;
    }
    
    print_result("C Sign -> Java Verify", 0, "Signing failed");
    return -1;
}

/* ====================================================
 * SM2 Tests
 * ==================================================== */

/* Test 5: Java SM3 -> C Verify */
int test_sm3_java_digest_c_verify(const char* java_digest_hex) {
    print_section("SM3 Test: Java Digest -> C Verify");
    
    char* c_digest_hex = NULL;
    int ret = crossmool_sm3_digest_str(TEST_MESSAGE, "UTF-8", &c_digest_hex);
    
    if (ret == CROSSMOOL_SUCCESS && c_digest_hex != NULL) {
        printf("  C computed digest: %s\n", c_digest_hex);
        printf("  Java digest:       %s\n", java_digest_hex);
        int match = (strcasecmp(c_digest_hex, java_digest_hex) == 0);
        print_result("Java Digest -> C Verify", match, match ? "Digests match" : "Digests mismatch");
        free(c_digest_hex);
        return match ? 0 : -1;
    }
    
    print_result("Java Digest -> C Verify", 0, "Digest computation failed");
    free(c_digest_hex);
    return -1;
}

/* Test 6: C SM3 -> Java Verify */
int test_sm3_c_digest_java_verify(void) {
    print_section("SM3 Test: C Digest -> Java Verify");
    
    char* c_digest_hex = NULL;
    int ret = crossmool_sm3_digest_str(TEST_MESSAGE, "UTF-8", &c_digest_hex);
    
    if (ret == CROSSMOOL_SUCCESS && c_digest_hex != NULL) {
        printf("  C digest (hex): %s\n", c_digest_hex);
        printf("  [Java should compute SM3('%s') and verify]\n", TEST_MESSAGE);
        print_result("C Digest -> Java Verify", 1, "Digest generated, please verify with Java");
        free(c_digest_hex);
        return 0;
    }
    
    print_result("C Digest -> Java Verify", 0, "Digest computation failed");
    return -1;
}

/* ====================================================
 * SM3 Tests
 * ==================================================== */

/* Test 7: Java SM4 Encrypt -> C Decrypt */
int test_sm4_java_encrypt_c_decrypt(const char* java_ciphertext_hex,
                                     const char* sm4_key_hex) {
    print_section("SM4 Test: Java Encrypt -> C Decrypt");
    
    unsigned char key[16];
    if (crossmool_sm4_parse_hex_key(sm4_key_hex, key) != CROSSMOOL_SUCCESS) {
        print_result("Java Encrypt -> C Decrypt", 0, "Invalid key");
        return -1;
    }
    
    unsigned char* plaintext = NULL;
    size_t plaintext_len = 0;
    int ret = crossmool_sm4_decrypt_ecb(key, java_ciphertext_hex, &plaintext, &plaintext_len);
    
    if (ret == CROSSMOOL_SUCCESS && plaintext != NULL) {
        printf("  C decrypted: %.*s\n", (int)plaintext_len, plaintext);
        int match = (plaintext_len == strlen(TEST_MESSAGE) && 
                     memcmp(plaintext, TEST_MESSAGE, plaintext_len) == 0);
        free(plaintext);
        print_result("Java Encrypt -> C Decrypt", match, match ? "Decrypted text matches" : "Mismatch");
        return match ? 0 : -1;
    }
    
    print_result("Java Encrypt -> C Decrypt", 0, "Decryption failed");
    return -1;
}

/* Test 8: C SM4 Encrypt -> Java Decrypt */
int test_sm4_c_encrypt_java_decrypt(const char* sm4_key_hex) {
    print_section("SM4 Test: C Encrypt -> Java Decrypt");
    
    unsigned char key[16];
    if (crossmool_sm4_parse_hex_key(sm4_key_hex, key) != CROSSMOOL_SUCCESS) {
        print_result("C Encrypt -> Java Decrypt", 0, "Invalid key");
        return -1;
    }
    
    char* ciphertext_hex = NULL;
    int ret = crossmool_sm4_encrypt_ecb(key, (const unsigned char*)TEST_MESSAGE, 
                                         strlen(TEST_MESSAGE), &ciphertext_hex);
    
    if (ret == CROSSMOOL_SUCCESS && ciphertext_hex != NULL) {
        printf("  C ciphertext (hex): %s\n", ciphertext_hex);
        printf("  [Java should decrypt this and verify]\n");
        print_result("C Encrypt -> Java Decrypt", 1, "Ciphertext generated, please verify with Java");
        free(ciphertext_hex);
        return 0;
    }
    
    print_result("C Encrypt -> Java Decrypt", 0, "Encryption failed");
    return -1;
}

/* ====================================================
 * SM4 Tests
 * ==================================================== */

/* Test 9: Java HMAC -> C Verify */
int test_hmac_java_c_verify(const char* java_hmac_hex) {
    print_section("HMAC-SM3 Test: Java HMAC -> C Verify");
    
    char* c_hmac_hex = NULL;
    int ret = crossmool_sm3_hmac_str(TEST_HMAC_KEY, "UTF-8", TEST_MESSAGE, "UTF-8", &c_hmac_hex);
    
    if (ret == CROSSMOOL_SUCCESS && c_hmac_hex != NULL) {
        printf("  C computed HMAC: %s\n", c_hmac_hex);
        printf("  Java HMAC:       %s\n", java_hmac_hex);
        int match = (strcasecmp(c_hmac_hex, java_hmac_hex) == 0);
        print_result("Java HMAC -> C Verify", match, match ? "HMACs match" : "HMACs mismatch");
        free(c_hmac_hex);
        return match ? 0 : -1;
    }
    
    print_result("Java HMAC -> C Verify", 0, "HMAC computation failed");
    free(c_hmac_hex);
    return -1;
}

/* Test 10: C HMAC -> Java Verify */
int test_hmac_c_java_verify(void) {
    print_section("HMAC-SM3 Test: C HMAC -> Java Verify");
    
    char* c_hmac_hex = NULL;
    int ret = crossmool_sm3_hmac_str(TEST_HMAC_KEY, "UTF-8", TEST_MESSAGE, "UTF-8", &c_hmac_hex);
    
    if (ret == CROSSMOOL_SUCCESS && c_hmac_hex != NULL) {
        printf("  C HMAC (hex): %s\n", c_hmac_hex);
        printf("  [Java should compute HMAC-SM3 and verify]\n");
        print_result("C HMAC -> Java Verify", 1, "HMAC generated, please verify with Java");
        free(c_hmac_hex);
        return 0;
    }
    
    print_result("C HMAC -> Java Verify", 0, "HMAC computation failed");
    return -1;
}

/* ====================================================
 * HMAC-SM3 Tests
 * ==================================================== */
/* ====================================================
 * Main Function - Get Java-generated data from command line arguments
 * ==================================================== */
int main(int argc, char* argv[]) {
    printf("Java-C SM2/SM3/SM4 Interoperability Test (C side)\n");
    printf("=================================================\n");
    
    /* Argument check - need 8 parameters + program name = argc 9 */
    if (argc < 9) {
        printf("Usage: %s <sm2_priv_hex> <sm2_pub_hex> <sm4_key_hex>\n", argv[0]);
        printf("            <java_ciphertext> <java_signature> <java_digest> <java_hmac>\n");
        printf("            <java_ciphertext_sm4>\n");
        printf("\nThis program will:\n");
        printf("  1. Decrypt Java ciphertext with C private key\n");
        printf("  2. Verify Java signature with C public key\n");
        printf("  3. Compare Java SM3 digest with C computed digest\n");
        printf("  4. Compare Java HMAC with C computed HMAC\n");
        printf("  5. Decrypt Java SM4 ciphertext\n");
        printf("  6. Generate C ciphertext/signature/digest for Java verification\n");
        return 1;
    }
    
    const char* sm2_private_key_hex = argv[1];
    const char* sm2_public_key_hex = argv[2];
    const char* sm4_key_hex = argv[3];
    const char* java_ciphertext = argv[4];
    const char* java_signature = argv[5];
    const char* java_digest = argv[6];
    const char* java_hmac = argv[7];
    const char* java_ciphertext_sm4 = argv[8];
    
    int pass_count = 0;
    int total_tests = 10;  // 10 tests: 2 SM2 + 2 SM2 sign + 2 SM3 + 2 HMAC + 2 SM4
    
    /* Run tests */
    if (test_sm2_java_encrypt_c_decrypt(java_ciphertext, sm2_private_key_hex) == 0) pass_count++;
    if (test_sm2_c_encrypt_java_decrypt(sm2_public_key_hex) == 0) pass_count++;
    if (test_sm2_java_sign_c_verify(java_signature, sm2_public_key_hex) == 0) pass_count++;
    if (test_sm2_c_sign_java_verify(sm2_private_key_hex) == 0) pass_count++;
    if (test_sm3_java_digest_c_verify(java_digest) == 0) pass_count++;
    if (test_sm3_c_digest_java_verify() == 0) pass_count++;
    if (test_hmac_java_c_verify(java_hmac) == 0) pass_count++;
    if (test_hmac_c_java_verify() == 0) pass_count++;
    if (test_sm4_java_encrypt_c_decrypt(java_ciphertext_sm4, sm4_key_hex) == 0) pass_count++;
    if (test_sm4_c_encrypt_java_decrypt(sm4_key_hex) == 0) pass_count++;
    
    /* Summary */
    printf("\n");
    printf("============================================================\n");
    printf(" Test Summary\n");
    printf("============================================================\n");
    printf("  Passed: %d / %d\n", pass_count, total_tests);
    printf("  Success Rate: %.1f%%\n", (pass_count * 100.0 / total_tests));
    printf("============================================================\n");
    
    return (pass_count == total_tests) ? 0 : 1;
}