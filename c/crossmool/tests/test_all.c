/**
 * crossmool-c 完整单元测试
 * 覆盖 SM2 / SM3 / SM4 / Util 所有公开 API
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

static int total = 0;
static int passed = 0;

#define TEST(name, expr) do { \
    total++; \
    if (expr) { \
        passed++; \
        printf("  [PASS] %s\n", name); \
    } else { \
        printf("  [FAIL] %s\n", name); \
    } \
} while(0)

/* ================================================================
 * 工具函数测试
 * ================================================================ */
static void test_util(void) {
    printf("\n--- Util Tests ---\n");

    /* HEX encode / decode */
    const unsigned char raw[] = {0xde, 0xad, 0xbe, 0xef};
    char* hex = NULL;
    TEST("hex_encode", crossmool_hex_encode(raw, 4, &hex) == CROSSMOOL_SUCCESS);
    TEST("hex_encode result", hex != NULL && strcmp(hex, "deadbeef") == 0);
    free(hex);

    unsigned char* dec = NULL;
    size_t dec_len = 0;
    TEST("hex_decode", crossmool_hex_decode("deadbeef", &dec, &dec_len) == CROSSMOOL_SUCCESS);
    TEST("hex_decode len", dec_len == 4);
    TEST("hex_decode data", dec != NULL && memcmp(dec, raw, 4) == 0);
    free(dec);

    /* is_hex */
    TEST("is_hex(valid)", crossmool_is_hex_string("abcd1234") == 1);
    TEST("is_hex(odd)", crossmool_is_hex_string("abc") == 0);
    TEST("is_hex(invalid)", crossmool_is_hex_string("xyz") == 0);

    /* Base64 encode / decode */
    char* b64 = NULL;
    const unsigned char hello[] = "Hello";
    TEST("base64_encode", crossmool_base64_encode(hello, 5, &b64) == CROSSMOOL_SUCCESS);
    TEST("base64_encode SGVsbG8=", b64 != NULL && strcmp(b64, "SGVsbG8=") == 0);
    
    unsigned char* b64_dec = NULL;
    size_t b64_dec_len = 0;
    TEST("base64_decode", crossmool_base64_decode(b64, &b64_dec, &b64_dec_len) == CROSSMOOL_SUCCESS);
    TEST("base64_decode len", b64_dec_len == 5);
    TEST("base64_decode data", b64_dec != NULL && memcmp(b64_dec, "Hello", 5) == 0);
    free(b64); free(b64_dec);

    /* is_base64 */
    TEST("is_base64(valid)", crossmool_is_base64_string("SGVsbG8=") == 1);
    TEST("is_base64(invalid)", crossmool_is_base64_string("!@#$") == 0);

    /* string_to_bytes / bytes_to_string */
    unsigned char* sb_data = NULL;
    size_t sb_len = 0;
    TEST("string_to_bytes UTF-8", crossmool_string_to_bytes("Test", NULL, &sb_data, &sb_len) == CROSSMOOL_SUCCESS);
    TEST("string_to_bytes len", sb_len == 4 && sb_data != NULL);
    free(sb_data);

    /* version */
    const char* ver = crossmool_version();
    TEST("version not null", ver != NULL);

    /* error_string */
    TEST("error_string(0)", strcmp(crossmool_error_string(0), "Success") == 0);
    TEST("error_string(-1)", strcmp(crossmool_error_string(-1), "Invalid parameter") == 0);
}

/* ================================================================
 * SM2 测试
 * ================================================================ */
static void test_sm2_keypair(void) {
    printf("\n--- SM2 Keypair Tests ---\n");

    /* pointer 版本 */
    crossmool_sm2_keypair_t* kp = NULL;
    TEST("generate_keypair", crossmool_sm2_generate_keypair(&kp) == CROSSMOOL_SUCCESS);
    TEST("kp not null", kp != NULL);
    TEST("private_key not null", kp->private_key != NULL);
    TEST("public_key not null", kp->public_key != NULL);
    TEST("private_key_hex not null", kp->private_key_hex != NULL);
    TEST("public_key_hex not null", kp->public_key_hex != NULL);
    TEST("private_key_hex len 64", strlen(kp->private_key_hex) == 64);
    TEST("public_key_hex len 130", strlen(kp->public_key_hex) == 130);

    /* convert to hex */
    TEST("keypair_to_hex", crossmool_sm2_keypair_to_hex(kp) == CROSSMOOL_SUCCESS);
    TEST("keypair_to_base64", crossmool_sm2_keypair_to_base64(kp) == CROSSMOOL_SUCCESS);
    TEST("private_key_base64 not null", kp->private_key_base64 != NULL);

    crossmool_sm2_keypair_free(kp);

    /* struct 直传版本 -- HEX */
    crossmool_sm2_keypair_t kh;
    memset(&kh, 0, sizeof(kh));
    TEST("generate_keypair_hex", crossmool_sm2_generate_keypair_hex(&kh) == CROSSMOOL_SUCCESS);
    TEST("kp_hex private", kh.private_key != NULL && strlen(kh.private_key) == 64);
    TEST("kp_hex public",  kh.public_key  != NULL && strlen(kh.public_key) == 130);
    free(kh.private_key); free(kh.public_key);

    /* struct 直传版本 -- Base64 */
    crossmool_sm2_keypair_t kb;
    memset(&kb, 0, sizeof(kb));
    TEST("generate_keypair_base64", crossmool_sm2_generate_keypair_base64(&kb) == CROSSMOOL_SUCCESS);
    TEST("kp_b64 private", kb.private_key != NULL);
    TEST("kp_b64 public",  kb.public_key  != NULL);
    free(kb.private_key); free(kb.public_key);
}

static void test_sm2_encrypt_decrypt(void) {
    printf("\n--- SM2 Encrypt/Decrypt Tests ---\n");

    crossmool_sm2_keypair_t* kp = NULL;
    crossmool_sm2_generate_keypair(&kp);

    /* 字符串接口 */
    char* ct_hex = NULL;
    TEST("encrypt string", crossmool_sm2_encrypt("Hello SM2!", NULL, kp->public_key_hex, &ct_hex) == CROSSMOOL_SUCCESS);
    TEST("ct_hex not null", ct_hex != NULL);

    char* pt_str = NULL;
    TEST("decrypt string", crossmool_sm2_decrypt(ct_hex, kp->private_key_hex, NULL, &pt_str) == CROSSMOOL_SUCCESS);
    TEST("decrypt match", pt_str != NULL && strcmp(pt_str, "Hello SM2!") == 0);
    free(pt_str);

    /* bytes 接口 */
    unsigned char* ct_bytes = NULL;
    size_t ct_len = 0;
    TEST("encrypt_bytes", crossmool_sm2_encrypt_bytes((const unsigned char*)"Bytes", 5,
                          kp->public_key_hex, &ct_bytes, &ct_len) == CROSSMOOL_SUCCESS);

    unsigned char* pt_bytes = NULL;
    size_t pt_len = 0;
    TEST("decrypt_bytes", crossmool_sm2_decrypt_bytes(ct_hex, kp->private_key_hex,
                          &pt_bytes, &pt_len) == CROSSMOOL_SUCCESS);
    TEST("decrypt_bytes match", pt_bytes != NULL && pt_len == 10 && memcmp(pt_bytes, "Hello SM2!", 10) == 0);
    free(pt_bytes);

    /* to_hex / to_base64 加密 */
    char* ct_hex2 = NULL;
    TEST("encrypt_to_hex", crossmool_sm2_encrypt_to_hex((const unsigned char*)"X", 1,
                           NULL, kp->public_key_hex, &ct_hex2) == CROSSMOOL_SUCCESS);
    free(ct_hex2);

    char* ct_b64 = NULL;
    TEST("encrypt_to_base64", crossmool_sm2_encrypt_to_base64((const unsigned char*)"Y", 1,
                             NULL, kp->public_key_hex, &ct_b64) == CROSSMOOL_SUCCESS);
    free(ct_b64);

    /* decrypt_to_string */
    char* pts2 = NULL;
    TEST("decrypt_to_string", crossmool_sm2_decrypt_to_string(ct_hex, kp->private_key_hex,
                              NULL, &pts2) == CROSSMOOL_SUCCESS);
    free(pts2);

    free(ct_hex); free(ct_bytes);
    crossmool_sm2_keypair_free(kp);
}

static void test_sm2_sign_verify(void) {
    printf("\n--- SM2 Sign/Verify Tests ---\n");

    crossmool_sm2_keypair_t* kp = NULL;
    crossmool_sm2_generate_keypair(&kp);

    const char* msg = "Message to sign";

    /* 字符串签名验签 */
    char* sig_hex = NULL;
    TEST("sign", crossmool_sm2_sign(msg, NULL, kp->private_key_hex, &sig_hex) == CROSSMOOL_SUCCESS);
    TEST("sig not null", sig_hex != NULL);

    int vr = crossmool_sm2_verify(msg, NULL, sig_hex, kp->public_key_hex);
    TEST("verify pass (correct)", vr == 1);

    vr = crossmool_sm2_verify("Wrong message", NULL, sig_hex, kp->public_key_hex);
    TEST("verify fail (wrong msg)", vr == 0);

    /* bytes 签名验签 */
    unsigned char* sig_bytes = NULL;
    size_t sig_len = 0;
    TEST("sign_bytes", crossmool_sm2_sign_bytes((const unsigned char*)msg, strlen(msg),
                       kp->private_key_hex, &sig_bytes, &sig_len) == CROSSMOOL_SUCCESS);
    free(sig_bytes);

    /* sign_to_hex */
    char* sig_hex2 = NULL;
    TEST("sign_to_hex", crossmool_sm2_sign_to_hex((const unsigned char*)msg, strlen(msg),
                         NULL, kp->private_key_hex, &sig_hex2) == CROSSMOOL_SUCCESS);
    free(sig_hex2);

    /* sign_to_base64 */
    char* sig_b64 = NULL;
    TEST("sign_to_base64", crossmool_sm2_sign_to_base64((const unsigned char*)msg, strlen(msg),
                           NULL, kp->private_key_hex, &sig_b64) == CROSSMOOL_SUCCESS);
    free(sig_b64);

    /* verify_bytes */
    vr = crossmool_sm2_verify_bytes((const unsigned char*)msg, strlen(msg), sig_hex, kp->public_key_hex);
    TEST("verify_bytes pass", vr == 1);

    free(sig_hex);
    crossmool_sm2_keypair_free(kp);
}

static void test_sm2_encrypt_sign_combo(void) {
    printf("\n--- SM2 Encrypt+Sign / Verify+Decrypt Tests ---\n");

    crossmool_sm2_keypair_t *enc_kp = NULL, *sign_kp = NULL;
    crossmool_sm2_generate_keypair(&enc_kp);
    crossmool_sm2_generate_keypair(&sign_kp);

    const char* content = "Combo test content";
    crossmool_sm2_cipher_sig_pair_t* pair = NULL;

    TEST("encrypt_sign", crossmool_sm2_encrypt_sign(content, NULL,
                          enc_kp->public_key_hex, sign_kp->private_key_hex,
                          &pair) == CROSSMOOL_SUCCESS);
    TEST("pair not null", pair != NULL);
    TEST("ciphertext not null", pair->ciphertext != NULL);
    TEST("signature not null", pair->signature != NULL);

    char* result = NULL;
    TEST("verify_decrypt", crossmool_sm2_verify_decrypt(
                            pair->ciphertext_hex, pair->signature_hex,
                            sign_kp->public_key_hex, enc_kp->private_key_hex,
                            NULL, &result) == CROSSMOOL_SUCCESS);
    TEST("combo content match", result != NULL && strcmp(result, content) == 0);
    free(result);

    /* 错误签名应拒绝 */
    char* wrong_result = NULL;
    int ret = crossmool_sm2_verify_decrypt(
        pair->ciphertext_hex, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        sign_kp->public_key_hex, enc_kp->private_key_hex,
        NULL, &wrong_result);
    TEST("verify_decrypt fail (wrong sig)", ret != CROSSMOOL_SUCCESS);

    crossmool_sm2_cipher_sig_pair_free(pair);
    crossmool_sm2_keypair_free(enc_kp);
    crossmool_sm2_keypair_free(sign_kp);
}

/* ================================================================
 * SM3 测试
 * ================================================================ */
static void test_sm3_digest(void) {
    printf("\n--- SM3 Digest Tests ---\n");

    /* bytes → hex */
    const unsigned char data[] = "hello sm3";
    char* dhex = NULL;
    TEST("digest_to_hex", crossmool_sm3_digest_to_hex(data, 9, &dhex) == CROSSMOOL_SUCCESS);
    TEST("digest_to_hex not null", dhex != NULL);
    TEST("digest_to_hex len 64", strlen(dhex) == 64);
    free(dhex);

    /* bytes → base64 */
    char* db64 = NULL;
    TEST("digest_to_base64", crossmool_sm3_digest_to_base64(data, 9, &db64) == CROSSMOOL_SUCCESS);
    TEST("digest_to_base64 not null", db64 != NULL);
    free(db64);

    /* raw digest */
    unsigned char raw_digest[CROSSMOOL_SM3_DIGEST_SIZE];
    TEST("digest raw", crossmool_sm3_digest(data, 9, raw_digest) == CROSSMOOL_SUCCESS);

    /* string digest */
    char* sd_hex = NULL;
    TEST("digest_str", crossmool_sm3_digest_str("test string", NULL, &sd_hex) == CROSSMOOL_SUCCESS);
    TEST("digest_str len 64", sd_hex != NULL && strlen(sd_hex) == 64);
    free(sd_hex);

    /* string digest base64 */
    char* sd_b64 = NULL;
    TEST("digest_str_to_base64", crossmool_sm3_digest_str_to_base64("test string", NULL, &sd_b64) == CROSSMOOL_SUCCESS);
    free(sd_b64);
}

static void test_sm3_hmac(void) {
    printf("\n--- SM3 HMAC Tests ---\n");

    /* hmac raw bytes */
    unsigned char key_raw[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                               0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                               0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                               0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    unsigned char data_raw[] = "data";
    unsigned char mac[32];
    TEST("hmac raw", crossmool_sm3_hmac(data_raw, 4, key_raw, 32, mac) == CROSSMOOL_SUCCESS);

    /* hmac_hex */
    char* key_hex = NULL;
    crossmool_hex_encode(key_raw, 32, &key_hex);
    char* hmac_hex = NULL;
    TEST("hmac_hex", crossmool_sm3_hmac_hex(data_raw, 4, key_hex, &hmac_hex) == CROSSMOOL_SUCCESS);
    TEST("hmac_hex len 64", hmac_hex != NULL && strlen(hmac_hex) == 64);
    free(hmac_hex); free(key_hex);

    /* hmac_str */
    char* hs = NULL;
    TEST("hmac_str", crossmool_sm3_hmac_str("mydata", NULL, "mykey", NULL, &hs) == CROSSMOOL_SUCCESS);
    TEST("hmac_str not null", hs != NULL);
    free(hs);

    /* hmac_to_hex / hmac_to_base64 */
    char* hh = NULL;
    TEST("hmac_to_hex", crossmool_sm3_hmac_to_hex("data", "key", &hh) == CROSSMOOL_SUCCESS);
    free(hh);

    char* hb = NULL;
    TEST("hmac_to_base64", crossmool_sm3_hmac_to_base64("data", "key", &hb) == CROSSMOOL_SUCCESS);
    free(hb);

    /* hmac_verify */
    char* my_hmac = NULL;
    crossmool_sm3_hmac_str("mydata", NULL, "mykey", NULL, &my_hmac);
    TEST("hmac_verify pass", crossmool_sm3_hmac_verify("mydata", NULL, "mykey", NULL, my_hmac) == 1);
    TEST("hmac_verify fail", crossmool_sm3_hmac_verify("mydata", NULL, "badkey", NULL, my_hmac) == 0);
    free(my_hmac);

    /* generate_hmac_key */
    unsigned char* gen_key = NULL;
    TEST("generate_hmac_key", crossmool_sm3_generate_hmac_key(32, &gen_key) == CROSSMOOL_SUCCESS);
    free(gen_key);
}

/* ================================================================
 * SM4 测试
 * ================================================================ */
static void test_sm4(void) {
    printf("\n--- SM4 Tests ---\n");

    /* 密钥生成 */
    unsigned char key[CROSSMOOL_SM4_KEY_SIZE];
    TEST("generate_key", crossmool_sm4_generate_key(key) == CROSSMOOL_SUCCESS);

    char* key_hex = NULL;
    TEST("generate_key_hex", crossmool_sm4_generate_key_hex(&key_hex) == CROSSMOOL_SUCCESS);
    TEST("key_hex len 32", key_hex != NULL && strlen(key_hex) == 32);
    free(key_hex);

    /* parse_hex_key */
    unsigned char parsed_key[CROSSMOOL_SM4_KEY_SIZE];
    TEST("parse_hex_key", crossmool_sm4_parse_hex_key("0123456789abcdef0123456789abcdef", parsed_key) == CROSSMOOL_SUCCESS);
    TEST("parsed key[0]", parsed_key[0] == 0x01);
    TEST("parsed key[15]", parsed_key[15] == 0xef);

    /* generate_iv */
    unsigned char iv[CROSSMOOL_SM4_GCM_IV_SIZE];
    TEST("generate_iv", crossmool_sm4_generate_iv(iv) == CROSSMOOL_SUCCESS);

    /* GCM HEX 加解密 */
    const unsigned char plain[] = "Hello, SM4 GCM!";
    char* ct_hex = NULL;
    TEST("encrypt_gcm_hex", crossmool_sm4_encrypt_gcm_hex(key, plain, 15, &ct_hex) == CROSSMOOL_SUCCESS);
    TEST("ct_hex not null", ct_hex != NULL);

    unsigned char* decrypted = NULL;
    size_t dec_len = 0;
    TEST("decrypt_gcm_hex", crossmool_sm4_decrypt_gcm_hex(key, ct_hex, &decrypted, &dec_len) == CROSSMOOL_SUCCESS);
    TEST("dec_gcm_hex len", dec_len == 15);
    TEST("dec_gcm_hex data", decrypted != NULL && memcmp(decrypted, plain, 15) == 0);
    free(decrypted);

    /* GCM Base64 加解密 */
    char* ct_b64 = NULL;
    TEST("encrypt_gcm_base64", crossmool_sm4_encrypt_gcm_base64(key, (const unsigned char*)"Base", 4,
                               &ct_b64) == CROSSMOOL_SUCCESS);

    unsigned char* dec_b64 = NULL;
    size_t dec_b64_len = 0;
    TEST("decrypt_gcm_base64", crossmool_sm4_decrypt_gcm_base64(key, ct_b64,
                               &dec_b64, &dec_b64_len) == CROSSMOOL_SUCCESS);
    TEST("dec_b64 data", dec_b64 != NULL && dec_b64_len == 4 && memcmp(dec_b64, "Base", 4) == 0);
    free(dec_b64); free(ct_b64);

    /* 向后兼容 GCM 函数 */
    char* ct_b64_old = NULL;
    TEST("encrypt_gcm (deprecated)", crossmool_sm4_encrypt_gcm(key, plain, 15, &ct_b64_old) == CROSSMOOL_SUCCESS);
    unsigned char* dec_old = NULL;
    size_t dec_old_len = 0;
    TEST("decrypt_gcm (deprecated)", crossmool_sm4_decrypt_gcm(key, ct_b64_old, &dec_old, &dec_old_len) == CROSSMOOL_SUCCESS);
    TEST("deprecated roundtrip", dec_old != NULL && dec_old_len == 15 && memcmp(dec_old, plain, 15) == 0);
    free(dec_old); free(ct_b64_old); free(ct_hex);

    /* 空明文加解密 */
    char* ct_empty = NULL;
    TEST("encrypt empty plaintext", crossmool_sm4_encrypt_gcm_hex(key, (const unsigned char*)"", 0, &ct_empty) == CROSSMOOL_SUCCESS);
    unsigned char* dec_empty = NULL;
    size_t dec_empty_len = 0;
    TEST("decrypt empty ciphertext", crossmool_sm4_decrypt_gcm_hex(key, ct_empty, &dec_empty, &dec_empty_len) == CROSSMOOL_SUCCESS);
    TEST("empty roundtrip len", dec_empty_len == 0);
    free(dec_empty); free(ct_empty);
}

/* ================================================================
 * 跨算法一致性测试
 * ================================================================ */
static void test_cross_consistency(void) {
    printf("\n--- Cross-Algorithm Consistency Tests ---\n");

    /* 多次加密应产生不同密文（随机 IV） */
    unsigned char key[CROSSMOOL_SM4_KEY_SIZE];
    crossmool_sm4_generate_key(key);

    char* ct1 = NULL, *ct2 = NULL;
    crossmool_sm4_encrypt_gcm_hex(key, (const unsigned char*)"test", 4, &ct1);
    crossmool_sm4_encrypt_gcm_hex(key, (const unsigned char*)"test", 4, &ct2);
    TEST("random IV different ct", ct1 != NULL && ct2 != NULL && strcmp(ct1, ct2) != 0);
    free(ct1); free(ct2);

    /* SM3 确定性 */
    char* d1 = NULL, *d2 = NULL;
    crossmool_sm3_digest_str("same_input", NULL, &d1);
    crossmool_sm3_digest_str("same_input", NULL, &d2);
    TEST("SM3 deterministic", strcmp(d1, d2) == 0);
    free(d1); free(d2);
}

int main(void) {
    printf("╔══════════════════════════════════════╗\n");
    printf("║   crossmool-c  Unit Test Suite       ║\n");
    printf("║   Version: %s                  ║\n", crossmool_version());
    printf("╚══════════════════════════════════════╝\n");

    test_util();
    test_sm2_keypair();
    test_sm2_encrypt_decrypt();
    test_sm2_sign_verify();
    test_sm2_encrypt_sign_combo();
    test_sm3_digest();
    test_sm3_hmac();
    test_sm4();
    test_cross_consistency();

    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  Results: %d / %d passed", passed, total);
    if (passed == total) {
        printf("  [ALL PASS]  ║\n");
    } else {
        printf("  [%d FAILED] ║\n", total - passed);
    }
    printf("╚══════════════════════════════════════╝\n");

    return (passed == total) ? 0 : 1;
}
