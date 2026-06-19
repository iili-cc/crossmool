#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"
#include "crossmool_sm2.h"
#include "crossmool_sm3.h"
#include "crossmool_sm4.h"

/* UTF-8 encoded test message: "Hello, (Chinese)...test data" */
static const unsigned char MSG[] = {
    0x48,0x65,0x6c,0x6c,0x6f,0x2c,0x20,0xe8,0xbf,0x99,0xe6,0x98,0xaf,0xe8,0xb7,0xa8,
    0xe8,0xaf,0xad,0xe8,0xa8,0x80,0xe5,0x9b,0xbd,0xe5,0xaf,0x86,0xe4,0xba,0x92,0xe9,
    0x80,0x9a,0xe6,0x80,0xa7,0xe6,0xb5,0x8b,0xe8,0xaf,0x95,0xe6,0x95,0xb0,0xe6,0x8d,
    0xae
};
#define MSG_LEN 49

#define SM4_KEY_HEX "0123456789abcdeffedcba9876543210"
#define HMAC_KEY_HEX "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
#define EXP_SM3 "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
#define EXP_SM3_HMAC "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"

/* Public keys: X.509 DER format */
#define ENC_PUB_HEX "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
#define SIG_PUB_HEX "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"

/* Raw 32-byte private keys (for signing, GmSSL needs raw or PKCS#8 with ECParameters) */
#define ENC_PRIV_RAW "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03"
#define SIG_PRIV_RAW "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3"

static void json_val(FILE* f, const char* key, const char* val, int* first) {
    if (*first) *first = 0; else fputs(",", f);
    fprintf(f, "\"%s\":\"", key);
    for (const char* p = val; p && *p; p++) {
        if (*p == '\\' || *p == '"') fputc('\\', f);
        if (*p == '\n') fputs("\\n", f);
        else fputc(*p, f);
    }
    fputc('"', f);
}

int main() {
    FILE* f = stdout;
    int first = 1;
    fputs("{\"lang\":\"c\"", f);

    unsigned char sm4_key[16];
    size_t i;
    crossmool_sm4_parse_hex_key(SM4_KEY_HEX, sm4_key);

    /* ========== SM2 Encrypt/Decrypt ========== */
    char* enc = NULL;
    int ret = crossmool_sm2_encrypt_to_hex(MSG, MSG_LEN, NULL, ENC_PUB_HEX, &enc);
    if (ret == 0 && enc) {
        json_val(f, "sm2_enc", enc, &first);
        unsigned char* dec = NULL;
        size_t dec_len;
        ret = crossmool_sm2_decrypt_bytes(enc, ENC_PRIV_RAW, &dec, &dec_len);
        int ok = (ret == 0 && dec_len == MSG_LEN && memcmp(dec, MSG, MSG_LEN) == 0);
        json_val(f, "sm2_enc_dec", ok ? "PASS" : "FAIL", &first);
        free(dec);
        free(enc);
    } else {
        json_val(f, "sm2_enc_dec", "FAIL", &first);
        fprintf(stderr, "C SM2 encrypt failed: ret=%d enc=%p\n", ret, (void*)enc);
        if (enc) free(enc);
    }

    /* ========== SM2 Sign/Verify (using raw 32-byte keys) ========== */
    char* sig = NULL;
    ret = crossmool_sm2_sign_to_hex(MSG, MSG_LEN, NULL, SIG_PRIV_RAW, &sig);
    if (ret == 0 && sig) {
        json_val(f, "sm2_sig", sig, &first);
        int vr = crossmool_sm2_verify_bytes(MSG, MSG_LEN, sig, SIG_PUB_HEX);
        json_val(f, "sm2_sig_ver", (vr == 1) ? "PASS" : "FAIL", &first);
        free(sig);
    } else {
        json_val(f, "sm2_sig_ver", "FAIL", &first);
        fprintf(stderr, "C SM2 sign failed: ret=%d\n", ret);
        if (sig) free(sig);
    }

    /* ========== SM2 EncSign + VerifyDec (C-specific API: signs ciphertext) ========== */
    crossmool_sm2_cipher_sig_pair_t* pair = NULL;
    ret = crossmool_sm2_encrypt_sign((const char*)MSG, NULL, ENC_PUB_HEX, SIG_PRIV_RAW, &pair);
    if (ret == 0 && pair) {
        char* dec2_result = NULL;
        int vr2 = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex,
                                                SIG_PUB_HEX, ENC_PRIV_RAW, NULL, &dec2_result);
        int ok2 = (vr2 == 0 && dec2_result && strcmp(dec2_result, (const char*)MSG) == 0);
        json_val(f, "sm2_enc_sig_ver_dec", ok2 ? "PASS" : "FAIL", &first);
        if (dec2_result) free(dec2_result);
        crossmool_sm2_cipher_sig_pair_free(pair);
    } else {
        json_val(f, "sm2_enc_sig_ver_dec", "FAIL", &first);
    }

    /* ========== SM3 ========== */
    char* sm3h = NULL;
    ret = crossmool_sm3_digest_to_hex(MSG, MSG_LEN, &sm3h);
    if (ret == 0 && sm3h) {
        json_val(f, "sm3_hash", sm3h, &first);
        json_val(f, "sm3", (strcmp(sm3h, EXP_SM3) == 0) ? "PASS" : "FAIL", &first);
        free(sm3h);
    } else { json_val(f, "sm3", "FAIL", &first); }

    /* ========== SM3-HMAC ========== */
    char* hmach = NULL;
    ret = crossmool_sm3_hmac_to_hex(HMAC_KEY_HEX, (const char*)MSG, &hmach);
    if (ret == 0 && hmach) {
        json_val(f, "sm3_hmac_hash", hmach, &first);
        json_val(f, "sm3_hmac", (strcmp(hmach, EXP_SM3_HMAC) == 0) ? "PASS" : "FAIL", &first);
        free(hmach);
    } else { json_val(f, "sm3_hmac", "FAIL", &first); }

    /* ========== SM4 GCM ========== */
    char* sm4e = NULL;
    ret = crossmool_sm4_encrypt_gcm_hex(sm4_key, MSG, MSG_LEN, &sm4e);
    if (ret == 0 && sm4e) {
        json_val(f, "sm4_enc", sm4e, &first);
        unsigned char* sm4d = NULL;
        size_t sm4d_len;
        ret = crossmool_sm4_decrypt_gcm_hex(sm4_key, sm4e, &sm4d, &sm4d_len);
        int m = (ret == 0 && sm4d_len == MSG_LEN && memcmp(sm4d, MSG, MSG_LEN) == 0);
        json_val(f, "sm4_enc_dec", m ? "PASS" : "FAIL", &first);
        free(sm4e); free(sm4d);
    } else { json_val(f, "sm4_enc_dec", "FAIL", &first); }

    fputs("}\n", f);
    return 0;
}
