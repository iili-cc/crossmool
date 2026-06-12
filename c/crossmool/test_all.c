/**
 * Crossmool-C Comprehensive Self-Test + Cross-Language Data Generator
 * Compile: cl /EHsc /std:c11 /I include /I gmssl_install/include test_all.c 
 *          src/error.c src/util_hex.c src/util_base64.c src/util_string.c 
 *          src/sm2.c src/sm3.c src/sm4.c 
 *          gmssl_install/lib/gmssl.lib /Fe:test_all.exe
 * Run: test_all.exe [--json]
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crossmool.h"

/* ===== Test Data (same as Python/Go/JS) ===== */
#define MSG "Hello, 这是跨语言国密互通性测试数据"
#define SM4_KEY_HEX "0123456789abcdeffedcba9876543210"
#define HMAC_KEY_HEX "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
#define EXP_SM3 "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
#define EXP_SM3_HMAC "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"

/* SM2 DER-encoded key pairs (from Java reference) */
#define ENC_PUB_DER_HEX  "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
#define ENC_PRIV_DER_HEX "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
#define SIG_PUB_DER_HEX  "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"
#define SIG_PRIV_DER_HEX "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"

/* ===== Helpers ===== */
#define TEST(name, expr) do { \
    int _r = (expr); \
    printf("  %-35s %s\n", name, _r == CROSSMOOL_SUCCESS ? "[PASS]" : "[FAIL]"); \
    if (_r != CROSSMOOL_SUCCESS) fprintf(stderr, "    err: %s\n", crossmool_error_string(_r)); \
} while(0)

#define CHECK(name, cond) printf("  %-35s %s\n", name, (cond) ? "[PASS]" : "[FAIL]")

/* ===== SM2 Tests ===== */
void test_sm2(void) {
    printf("\n=== SM2 Self-Test ===\n");

    /* 1. Encrypt with DER public key, decrypt with DER private key */
    char *cipher = NULL;
    int ret = crossmool_sm2_encrypt(MSG, "UTF-8", ENC_PUB_DER_HEX, &cipher);
    CHECK("SM2 Encrypt", ret == CROSSMOOL_SUCCESS && cipher != NULL);
    if (cipher) {
        printf("    Cipher(%d): %.80s...\n", (int)strlen(cipher), cipher);
    }

    char *decrypted = NULL;
    if (cipher) {
        ret = crossmool_sm2_decrypt(cipher, ENC_PRIV_DER_HEX, "UTF-8", &decrypted);
        CHECK("SM2 Decrypt", ret == CROSSMOOL_SUCCESS && decrypted != NULL && strcmp(decrypted, MSG) == 0);
        if (decrypted) printf("    Plain: %s\n", decrypted);
    }

    /* 2. Sign with DER private key, verify with DER public key */
    char *signature = NULL;
    ret = crossmool_sm2_sign(MSG, "UTF-8", SIG_PRIV_DER_HEX, &signature);
    CHECK("SM2 Sign", ret == CROSSMOOL_SUCCESS && signature != NULL);
    if (signature) {
        printf("    Sig(%d): %.80s...\n", (int)strlen(signature), signature);
    }

    if (signature) {
        int vret = crossmool_sm2_verify(MSG, "UTF-8", signature, SIG_PUB_DER_HEX);
        CHECK("SM2 Verify", vret == 1);
    }

    /* 3. Encrypt+Sign, Verify+Decrypt */
    crossmool_sm2_cipher_sig_pair_t *pair = NULL;
    ret = crossmool_sm2_encrypt_sign(MSG, "UTF-8", ENC_PUB_DER_HEX, SIG_PRIV_DER_HEX, &pair);
    CHECK("SM2 EncryptSign", ret == CROSSMOOL_SUCCESS && pair != NULL);

    if (pair && pair->ciphertext_hex && pair->signature_hex) {
        char *result = NULL;
        ret = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex, 
                                           SIG_PUB_DER_HEX, ENC_PRIV_DER_HEX, "UTF-8", &result);
        CHECK("SM2 VerifyDecrypt", ret == CROSSMOOL_SUCCESS && result != NULL && strcmp(result, MSG) == 0);
        if (result) free(result);
        crossmool_sm2_cipher_sig_pair_free(pair);
    }

    /* Cleanup */
    if (cipher) free(cipher);
    if (decrypted) free(decrypted);
    if (signature) free(signature);
}

/* ===== SM3 Tests ===== */
void test_sm3(void) {
    printf("\n=== SM3 Self-Test ===\n");

    /* SM3 Digest */
    char *digest = NULL;
    int ret = crossmool_sm3_digest_str(MSG, "UTF-8", &digest);
    CHECK("SM3 Digest", ret == CROSSMOOL_SUCCESS && digest != NULL);
    if (digest) {
        int match = (strcmp(digest, EXP_SM3) == 0);
        CHECK("SM3 Digest matches expected", match);
        printf("    Expected: %s\n    Got:      %s\n", EXP_SM3, digest);
        free(digest);
    }

    /* SM3-HMAC */
    char *hmac_result = NULL;
    ret = crossmool_sm3_hmac_hex(HMAC_KEY_HEX, (const unsigned char*)MSG, strlen(MSG), &hmac_result);
    CHECK("SM3-HMAC", ret == CROSSMOOL_SUCCESS && hmac_result != NULL);
    if (hmac_result) {
        int match = (strcmp(hmac_result, EXP_SM3_HMAC) == 0);
        CHECK("SM3-HMAC matches expected", match);
        printf("    Expected: %s\n    Got:      %s\n", EXP_SM3_HMAC, hmac_result);
        free(hmac_result);
    }
}

/* ===== SM4 Tests ===== */
void test_sm4(void) {
    printf("\n=== SM4 GCM Self-Test ===\n");

    /* Parse fixed key */
    unsigned char key[16];
    int ret = crossmool_sm4_parse_hex_key(SM4_KEY_HEX, key);
    CHECK("SM4 Parse Key", ret == CROSSMOOL_SUCCESS);

    /* Encrypt (HEX output) */
    char *cipher_hex = NULL;
    ret = crossmool_sm4_encrypt_gcm_hex(key, (const unsigned char*)MSG, strlen(MSG), &cipher_hex);
    CHECK("SM4 GCM Encrypt (Hex)", ret == CROSSMOOL_SUCCESS && cipher_hex != NULL);
    if (cipher_hex) {
        printf("    Cipher(%d): %.80s...\n", (int)strlen(cipher_hex), cipher_hex);
    }

    /* Decrypt from HEX */
    if (cipher_hex) {
        unsigned char *plain = NULL;
        size_t plain_len = 0;
        ret = crossmool_sm4_decrypt_gcm_hex(key, cipher_hex, &plain, &plain_len);
        int ok = (ret == CROSSMOOL_SUCCESS && plain != NULL && 
                  plain_len == strlen(MSG) && memcmp(plain, MSG, plain_len) == 0);
        CHECK("SM4 GCM Decrypt (Hex)", ok);
        if (plain) free(plain);
    }

    /* Encrypt (Base64 output) */
    char *cipher_b64 = NULL;
    ret = crossmool_sm4_encrypt_gcm_base64(key, (const unsigned char*)MSG, strlen(MSG), &cipher_b64);
    CHECK("SM4 GCM Encrypt (Base64)", ret == CROSSMOOL_SUCCESS && cipher_b64 != NULL);

    /* Decrypt from Base64 */
    if (cipher_b64) {
        unsigned char *plain2 = NULL;
        size_t plain_len2 = 0;
        ret = crossmool_sm4_decrypt_gcm_base64(key, cipher_b64, &plain2, &plain_len2);
        int ok = (ret == CROSSMOOL_SUCCESS && plain2 != NULL && 
                  plain_len2 == strlen(MSG) && memcmp(plain2, MSG, plain_len2) == 0);
        CHECK("SM4 GCM Decrypt (Base64)", ok);
        if (plain2) free(plain2);
    }

    if (cipher_hex) free(cipher_hex);
    if (cipher_b64) free(cipher_b64);
}

/* ===== JSON output for cross-language testing ===== */
void output_json(void) {
    char *cipher = NULL, *signature = NULL, *digest = NULL, *hmac = NULL, *sm4_enc = NULL;
    
    crossmool_sm2_encrypt(MSG, "UTF-8", ENC_PUB_DER_HEX, &cipher);
    crossmool_sm2_sign(MSG, "UTF-8", SIG_PRIV_DER_HEX, &signature);
    crossmool_sm3_digest_str(MSG, "UTF-8", &digest);
    crossmool_sm3_hmac_hex(HMAC_KEY_HEX, (const unsigned char*)MSG, strlen(MSG), &hmac);
    
    unsigned char key[16];
    crossmool_sm4_parse_hex_key(SM4_KEY_HEX, key);
    crossmool_sm4_encrypt_gcm_hex(key, (const unsigned char*)MSG, strlen(MSG), &sm4_enc);
    
    printf("{");
    printf("\"lang\":\"c\",");
    printf("\"msg\":\"%s\",", MSG);
    printf("\"sm2_enc\":\"%s\",", cipher ? cipher : "");
    printf("\"sm2_sig\":\"%s\",", signature ? signature : "");
    printf("\"sm3_hash\":\"%s\",", digest ? digest : "");
    printf("\"sm3_hmac_hash\":\"%s\",", hmac ? hmac : "");
    printf("\"sm4_enc\":\"%s\"", sm4_enc ? sm4_enc : "");
    printf("}\n");
    
    if (cipher) free(cipher);
    if (signature) free(signature);
    if (digest) free(digest);
    if (hmac) free(hmac);
    if (sm4_enc) free(sm4_enc);
}

/* ===== Main ===== */
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--json") == 0) {
        output_json();
        return 0;
    }
    
    printf("========================================\n");
    printf("  Crossmool-C Comprehensive Self-Test\n");
    printf("  Version: %s\n", crossmool_version());
    printf("========================================\n");

    test_sm2();
    test_sm3();
    test_sm4();

    printf("\n========================================\n");
    printf("  All C Self-Tests Complete\n");
    printf("========================================\n");
    return 0;
}
