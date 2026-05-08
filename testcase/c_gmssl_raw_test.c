#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "crossmool.h"
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>

/* 我们需要 GmSSL 的底层接口来调试，但 crossmool.h 已经禁用了 DEBUG。
   直接调用 GmSSL 内部函数来输出 Z 值和 digest。 */

int main() {
    /* Setup key */
    SM2_KEY key;
    memset(&key, 0, sizeof(key));

    /* Raw private key and public key */
    uint8_t priv_bytes[32] = {
        0x72,0xe9,0x94,0xf7,0xae,0xe0,0xa4,0xfe,0x1d,0x50,0x7f,0x59,0x18,0x4c,0xe1,0xa0,
        0x92,0xc0,0x56,0x91,0x65,0x94,0x43,0xba,0x17,0xb0,0xdc,0xd2,0x5a,0x8a,0xb0,0x57
    };
    uint8_t pub_bytes[65] = {
        0x04,
        0x8e,0x9c,0xad,0x1b,0x86,0x38,0x29,0x9d,0xc3,0xd6,0x1b,0xb2,0x7c,0x40,0xdb,0x51,
        0xff,0x63,0xf5,0x9a,0xc9,0x3f,0xf9,0xef,0x9c,0xd0,0xc5,0x3a,0x3e,0x06,0x0b,0x3b,
        0x37,0x9c,0xfb,0xcc,0x68,0xbd,0xbe,0x98,0x01,0x29,0xa6,0x84,0x75,0x0a,0xef,0x5c,
        0x76,0x7e,0xd1,0x73,0xd8,0x5b,0xdf,0x3e,0x64,0x82,0x87,0x01,0xe0,0xff,0x54,0xd4
    };

    sm2_key_set_private_key(&key, priv_bytes);
    sm2_point_from_octets(&key.public_key, pub_bytes, 65);

    /* Compute Z value */
    uint8_t z[32];
    sm2_compute_z(z, &key.public_key, SM2_DEFAULT_ID, 16);

    printf("Z value: ");
    for (int i = 0; i < 32; i++) printf("%02x", z[i]);
    printf("\n");

    /* Sign "Hello, Crossmool!" */
    const char* msg = "Hello, Crossmool!";
    SM2_SIGN_CTX ctx;
    uint8_t sig_buf[128];
    size_t sig_len = 0;

    sm2_sign_init(&ctx, &key, SM2_DEFAULT_ID, 16);
    sm2_sign_update(&ctx, (const uint8_t*)msg, strlen(msg));
    int sign_ret = sm2_sign_finish(&ctx, sig_buf, &sig_len);

    printf("Sign ret: %d, sig_len: %d\n", sign_ret, (int)sig_len);
    printf("Signature hex: ");
    for (size_t i = 0; i < sig_len; i++) printf("%02x", sig_buf[i]);
    printf("\n");
    printf("Signature first byte: 0x%02x\n", sig_buf[0]);

    /* Self verify */
    SM2_SIGN_CTX vctx;
    sm2_verify_init(&vctx, &key, SM2_DEFAULT_ID, 16);
    sm2_verify_update(&vctx, (const uint8_t*)msg, strlen(msg));
    int vret = sm2_verify_finish(&vctx, sig_buf, sig_len);
    printf("Self verify (GmSSL): %s\n", vret == 1 ? "SUCCESS" : "FAILED");

    /* Now verify Java signature */
    printf("\n=== Verify Java signature ===\n");
    const uint8_t java_sig[] = {
        0x30,0x45,0x02,0x21,0x00,0xc7,0x5c,0xb7,0x82,0xf8,0x22,0xa9,0x92,0x81,0xd2,0x80,
        0xbc,0xe9,0xaf,0x15,0x62,0x65,0x25,0x2b,0x60,0xf1,0xe2,0x8b,0x74,0xf3,0x4d,0x1e,
        0x43,0x61,0xc2,0x98,0xa8,0x02,0x20,0x14,0x8a,0x04,0xbe,0x09,0x37,0x09,0x89,0x1f,
        0x64,0x48,0x4e,0xb6,0x57,0xfd,0x54,0xb1,0xea,0xb5,0xc2,0x0c,0x93,0x3b,0x81,0x33,
        0xbd,0xeb,0xe7,0xde,0xa4,0x88,0x80,0xf
    };
    size_t java_sig_len = sizeof(java_sig);

    /* Verify with GmSSL raw API */
    SM2_SIGN_CTX vctx2;
    sm2_verify_init(&vctx2, &key, SM2_DEFAULT_ID, 16);
    sm2_verify_update(&vctx2, (const uint8_t*)msg, strlen(msg));
    int vret2 = sm2_verify_finish(&vctx2, java_sig, java_sig_len);
    printf("Java sig verify (GmSSL raw): %s\n", vret2 == 1 ? "SUCCESS" : "FAILED");

    /* Also try with ciphertext message */
    printf("\n=== Verify Java CT signature ===\n");
    const char* ct_msg = "046a2146cffa0e592b74f49304a75eb73449be5ae5f7cabac4a3938ae34539207472a2b912701a096ad7182772cede4439cc0642c3b56d123ca9c8b11b569ab94197d41b436a9240ef89ed76d01bee13129c5abc6aefa0d262424f147382f478fae20b93b2b671f0a33eec6a00830f44a191";

    SM2_SIGN_CTX vctx3;
    sm2_verify_init(&vctx3, &key, SM2_DEFAULT_ID, 16);
    sm2_verify_update(&vctx3, (const uint8_t*)ct_msg, strlen(ct_msg));
    int vret3 = sm2_verify_finish(&vctx3, java_sig, java_sig_len);
    printf("Java CT sig verify (GmSSL raw): %s\n", vret3 == 1 ? "SUCCESS" : "FAILED");

    return 0;
}
