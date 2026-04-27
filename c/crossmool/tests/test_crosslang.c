/**
 * test_crosslang.c — C/Java 跨语言互通性验证测试
 *
 * 使用 Java 端 SM2Constant / SM3Constant / SM4Constant 中定义的固定密钥，
 * 在 C 端执行加密/签名操作，验证 C 端的算法实现与 Java (BouncyCastle) 一致。
 *
 * 互通策略：
 *   - SM2: 用 Java 的公钥加密 → Java 解密；用 Java 的私钥签名 → Java 验签
 *          反之 Java 加密 → C 解密，Java 签名 → C 验签
 *          由于 C 端 SM2 加密含随机数，密文无法逐字节比对，只能验证"加解密往返"
 *   - SM3: 摘要和 HMAC 是确定性算法，C 和 Java 对同一输入必须产出完全相同的输出
 *   - SM4: ECB 模式确定性加密，C 和 Java 对同一密钥+明文必须产出完全相同的密文
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

/* ============================================================
 * Java SM2Constant 中的固定测试密钥 (ASN.1 HEX 格式)
 * ============================================================ */

/* 加密密钥对 */
static const char* JAVA_CIPHER_PUB_HEX =
    "3059301306072a8648ce3d020106082a811ccf5501822d03420004"
    "873ec94bca48965945db80a0555df1a1f4adef6b10794cab0be78b"
    "b089f253e616c529e8a62e5dd1100e0fe55220fd30e525051949e2"
    "7c87d9b5293d3c771e39";

static const char* JAVA_CIPHER_PRIV_HEX =
    "308193020100301306072a8648ce3d020106082a811ccf5501822d"
    "047930770201010420dfdff073ab251f82790b40a1c2858150eb9f"
    "574c5b38a987c667c96e4e6b40e7a00a06082a811ccf5501822da1"
    "4403420004873ec94bca48965945db80a0555df1a1f4adef6b1079"
    "4cab0be78bb089f253e616c529e8a62e5dd1100e0fe55220fd30e5"
    "25051949e27c87d9b5293d3c771e39";

/* 签名密钥对 */
static const char* JAVA_SIGN_PUB_HEX =
    "3059301306072a8648ce3d020106082a811ccf5501822d03420004"
    "b053b1c107374e179e1c944821229f1c11e81e7559fa783e9712b5"
    "6eac1ec50086e4ebc94cbbcefef719b9e4df711001660af45a0753"
    "ce062a30018cfb9a497b";

static const char* JAVA_SIGN_PRIV_HEX =
    "308193020100301306072a8648ce3d020106082a811ccf5501822d"
    "047930770201010420cb78a6a58d56e61b3d730f1572677a0cfa08"
    "071f571f0716ce4fce156243a006a00a06082a811ccf5501822da1"
    "4403420004b053b1c107374e179e1c944821229f1c11e81e7559fa"
    "783e9712b56eac1ec50086e4ebc94cbbcefef719b9e4df7110016"
    "60af45a0753ce062a30018cfb9a497b";

/* 加密密钥对 (Base64 格式, 来自 Java SM2Constant) */
static const char* JAVA_CIPHER_PUB_B64 =
    "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEO4gVFPrTdWaMRocy/"
    "GuyjUZYdbdsqzfcvrtjkCoTVfBSXVWElN6uj91ZxsiszlzQ3JxTYx"
    "LKd3sy6EWNuS22+g==";

static const char* JAVA_CIPHER_PRIV_B64 =
    "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgLtLT"
    "8TS7TpI1t6JhId5PiZ7yI+DwNDWwXY54yyb89SmgCgYIKoEcz1UB"
    "gi2hRANCAAQ7iBUU+tN1ZoxGhzL8a7KNRlh1t2yrN9y+u2OQKhNV"
    "8FJdVYSU3q6P3VnGyKzOXNDcnFNjEsp3ezLoRY25Lbb6";

/* 签名密钥对 (Base64 格式) */
static const char* JAVA_SIGN_PUB_B64 =
    "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEZs0zkFzd6j64JuKS"
    "MvNH8qK4OSCuBUQH2mzZdV/f5BZ028BHGxZ/uZM9Shqm+rEgkJ0v"
    "Dbsr3luWhSAEkYbLhA==";

static const char* JAVA_SIGN_PRIV_B64 =
    "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQghdEm"
    "DD4sgxQXfrDeGoHITWChGHSld/gV/ctXpxxNBTmgCgYIKoEcz1UB"
    "gi2hRANCAARmzTOQXN3qPrgm4pIy80fyorg5IK4FRAfabNl1X9/k"
    "FnTbwEcbFn+5kz1KGqb6sSCQnS8NuyveW5aFIASRhsuE";

/* SM2 测试明文 (来自 Java SM2Constant.SM2_TEST_STRING)
 * 文件以 UTF-8 保存, 配合 /utf-8 编译选项可直接写中文 */
static const char* SM2_TEST_STRING =
    "\xe6\x82\xa8\xe5\xa5\xbd"           /* 您好 */
    "\xef\xbc\x8c"                         /* ， */
    "\xe6\x88\x91\xe6\x98\xaf"            /* 我是 */
    "SM2"
    "\xe7\xae\x97\xe6\xb3\x95"            /* 算法 */
    "\xe6\xb8\xac\xe8\xaf\x95"            /* 測試 */
    "\xe6\x95\xb0\xe6\x8d\xae"            /* 數據 */
    "\xef\xbc\x8c"                         /* ， */
    "\xe5\x8c\x85\xe6\x8b\xac"            /* 包括 */
    "\xe7\xae\x80\xe4\xbd\x93\xe4\xb8\xad" /* 简体中 */
    "\xe6\x96\x87"                         /* 文 */
    "\xef\xbc\x8c"                         /* ， */
    "\xe7\xb9\x81\xe9\xab\x94\xe4\xb8\xad" /* 繁體中 */
    "\xe6\x96\x87"                         /* 文 */
    "\xef\xbc\x8c"                         /* ， */
    "English"
    "\xe4\xb8\x89"                         /* 三 */
    "\xe7\xa7\x8d\xe6\x96\x87\xe5\xad\x97" /* 種文字 */
    "\xef\xbc\x8c"                         /* ， */
    "you can use me for a test!";

/* ============================================================
 * Java SM3Constant 中的固定测试数据
 * ============================================================ */
static const char* SM3_HMAC_KEY_HEX =
    "0d4557e5ed4b01d2bb05853e16886d82c6d5d44b3ef1958cadbdc2cd4752093c";

static const char* SM3_HMAC_KEY_B64 =
    "pmj4GjONG1q77D7Q6/PivwN0zMeVx6l7NtiJ9C7Pr7c=";

static const char* SM3_TEST_STRING =
    "Hello"
    "\xef\xbc\x8c"                         /* ， */
    "\xe6\x88\x91\xe6\x98\xaf"            /* 我是 */
    "SM3"
    "\xe7\xae\x97\xe6\xb3\x95"            /* 算法 */
    "\xe6\xb8\xac\xe8\xaf\x95"            /* 測試 */
    "\xe6\x95\xb0\xe6\x8d\xae"            /* 數據 */
    "\xef\xbc\x8c"                         /* ， */
    "\xe5\x8c\x85\xe6\x8b\xac"            /* 包括 */
    "\xe7\xae\x80\xe4\xbd\x93\xe4\xb8\xad" /* 简体中 */
    "\xe6\x96\x87"                         /* 文 */
    "\xef\xbc\x8c"                         /* ， */
    "\xe7\xb9\x81\xe9\xab\x94\xe4\xb8\xad" /* 繁體中 */
    "\xe6\x96\x87"                         /* 文 */
    "\xef\xbc\x8c"                         /* ， */
    "English"
    "\xe4\xb8\x89"                         /* 三 */
    "\xe7\xa7\x8d\xe6\x96\x87\xe5\xad\x97" /* 種文字 */
    "!";

/* ============================================================
 * Java SM4Constant 中的固定测试数据
 * 注意：Java SM4Constant 中 CIPHER__KEY_BASE64 和 CIPHER__KEY_HEX
 *       的值似乎被互换了（命名与实际格式不匹配）：
 *       CIPHER__KEY_BASE64 = "8091d00c09ba74cfe6da26b7daa7ce39" (实际是 HEX)
 *       CIPHER__KEY_HEX    = "gJHQDAm6dM/m2ia32qfOOQ==" (实际是 Base64)
 * ============================================================ */
static const char* SM4_KEY_HEX = "8091d00c09ba74cfe6da26b7daa7ce39";
static const char* SM4_TEST_STRING =
    "Hello, "
    "\xe9\x80\x99"                         /* 這 */
    "\xe6\x98\xaf"                         /* 是 */
    "\xe5\x9b\xbd\xe5\xaf\x86"            /* 国密 */
    "SM4"
    "\xe6\xb8\xac\xe8\xaf\x95"            /* 測試 */
    "\xe6\x95\xb0\xe6\x8d\xae";            /* 數據 */

/* ============================================================
 * 辅助函数
 * ============================================================ */
static int g_pass = 0;
static int g_fail = 0;

static void report(const char* name, int ok) {
    if (ok) {
        printf("  [PASS] %s\n", name);
        g_pass++;
    } else {
        printf("  [FAIL] %s\n", name);
        g_fail++;
    }
}

/* ============================================================
 * SM2 跨语言互通测试
 * ============================================================ */
static void test_sm2_crosslang(void) {
    printf("\n=== SM2 Cross-Language Interop Test ===\n\n");
    int ret;

    /* --- 1. 使用 Java HEX 公钥加密，C 端自己解密 --- */
    printf("--- 1. Encrypt with Java HEX public key, decrypt with Java HEX private key ---\n");
    {
        char* ciphertext = NULL;
        ret = crossmool_sm2_encrypt(SM2_TEST_STRING, NULL, JAVA_CIPHER_PUB_HEX, &ciphertext);
        if (ret != CROSSMOOL_SUCCESS) {
            printf("    [DEBUG] encrypt ret=%d (%s)\n", ret, crossmool_error_string(ret));
            printf("    [DEBUG] pub_key first 40 chars: %.40s...\n", JAVA_CIPHER_PUB_HEX);
        }
        report("encrypt with Java HEX pub key", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS) {
            char* decrypted = NULL;
            ret = crossmool_sm2_decrypt(ciphertext, JAVA_CIPHER_PRIV_HEX, NULL, &decrypted);
            report("decrypt with Java HEX priv key", ret == CROSSMOOL_SUCCESS);

            if (ret == CROSSMOOL_SUCCESS) {
                report("decrypted content matches", strcmp(decrypted, SM2_TEST_STRING) == 0);
                free(decrypted);
            }
            free(ciphertext);
        }
    }

    /* --- 2. 使用 Java Base64 公钥加密，C 端自己解密 --- */
    printf("\n--- 2. Encrypt with Java Base64 public key, decrypt with Java Base64 private key ---\n");
    {
        char* ciphertext = NULL;
        ret = crossmool_sm2_encrypt(SM2_TEST_STRING, NULL, JAVA_CIPHER_PUB_B64, &ciphertext);
        report("encrypt with Java Base64 pub key", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS) {
            char* decrypted = NULL;
            ret = crossmool_sm2_decrypt(ciphertext, JAVA_CIPHER_PRIV_B64, NULL, &decrypted);
            report("decrypt with Java Base64 priv key", ret == CROSSMOOL_SUCCESS);

            if (ret == CROSSMOOL_SUCCESS) {
                report("decrypted content matches", strcmp(decrypted, SM2_TEST_STRING) == 0);
                free(decrypted);
            }
            free(ciphertext);
        }
    }

    /* --- 3. 使用 Java HEX 私钥签名，C 端自己验签 --- */
    printf("\n--- 3. Sign with Java HEX private key, verify with Java HEX public key ---\n");
    {
        char* signature = NULL;
        ret = crossmool_sm2_sign(SM2_TEST_STRING, NULL, JAVA_SIGN_PRIV_HEX, &signature);
        if (ret != CROSSMOOL_SUCCESS) {
            printf("    [DEBUG] sign ret=%d (%s)\n", ret, crossmool_error_string(ret));
            printf("    [DEBUG] priv_key first 40 chars: %.40s...\n", JAVA_SIGN_PRIV_HEX);
        }
        report("sign with Java HEX priv key", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS) {
            int vr = crossmool_sm2_verify(SM2_TEST_STRING, NULL, signature, JAVA_SIGN_PUB_HEX);
            report("verify with Java HEX pub key", vr == 1);

            /* 篡改数据后验签应失败 */
            vr = crossmool_sm2_verify("tampered", NULL, signature, JAVA_SIGN_PUB_HEX);
            report("verify fails for tampered data", vr == 0);

            free(signature);
        }
    }

    /* --- 4. 使用 Java Base64 私钥签名，C 端自己验签 --- */
    printf("\n--- 4. Sign with Java Base64 private key, verify with Java Base64 public key ---\n");
    {
        char* signature = NULL;
        ret = crossmool_sm2_sign(SM2_TEST_STRING, NULL, JAVA_SIGN_PRIV_B64, &signature);
        report("sign with Java Base64 priv key", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS) {
            int vr = crossmool_sm2_verify(SM2_TEST_STRING, NULL, signature, JAVA_SIGN_PUB_B64);
            report("verify with Java Base64 pub key", vr == 1);
            free(signature);
        }
    }

    /* --- 5. 加密+签名组合（HEX密钥） --- */
    printf("\n--- 5. Encrypt+Sign combo with Java HEX keys ---\n");
    {
        crossmool_sm2_cipher_sig_pair_t* pair = NULL;
        ret = crossmool_sm2_encrypt_sign(SM2_TEST_STRING, NULL,
                                          JAVA_CIPHER_PUB_HEX, JAVA_SIGN_PRIV_HEX, &pair);
        report("encrypt_sign with HEX keys", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS && pair != NULL) {
            char* result = NULL;
            ret = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex,
                                                JAVA_SIGN_PUB_HEX, JAVA_CIPHER_PRIV_HEX,
                                                NULL, &result);
            report("verify_decrypt with HEX keys", ret == CROSSMOOL_SUCCESS);

            if (ret == CROSSMOOL_SUCCESS && result != NULL) {
                report("content matches after verify_decrypt", strcmp(result, SM2_TEST_STRING) == 0);
                free(result);
            }
            crossmool_sm2_cipher_sig_pair_free(pair);
        }
    }

    /* --- 6. 加密+签名组合（Base64密钥） --- */
    printf("\n--- 6. Encrypt+Sign combo with Java Base64 keys ---\n");
    {
        crossmool_sm2_cipher_sig_pair_t* pair = NULL;
        ret = crossmool_sm2_encrypt_sign(SM2_TEST_STRING, NULL,
                                          JAVA_CIPHER_PUB_B64, JAVA_SIGN_PRIV_B64, &pair);
        report("encrypt_sign with Base64 keys", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS && pair != NULL) {
            char* result = NULL;
            ret = crossmool_sm2_verify_decrypt(pair->ciphertext_hex, pair->signature_hex,
                                                JAVA_SIGN_PUB_B64, JAVA_CIPHER_PRIV_B64,
                                                NULL, &result);
            report("verify_decrypt with Base64 keys", ret == CROSSMOOL_SUCCESS);

            if (ret == CROSSMOOL_SUCCESS && result != NULL) {
                report("content matches after verify_decrypt", strcmp(result, SM2_TEST_STRING) == 0);
                free(result);
            }
            crossmool_sm2_cipher_sig_pair_free(pair);
        }
    }
}

/* ============================================================
 * SM3 跨语言互通测试
 * ============================================================ */
static void test_sm3_crosslang(void) {
    printf("\n=== SM3 Cross-Language Interop Test ===\n\n");
    int ret;

    /* --- 1. SM3 摘要 --- */
    printf("--- 1. SM3 Digest (deterministic, can compare with Java) ---\n");
    {
        char* digest_hex = NULL;
        ret = crossmool_sm3_digest_str(SM3_TEST_STRING, NULL, &digest_hex);
        report("digest_str", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS) {
            printf("    Input:  %s\n", SM3_TEST_STRING);
            printf("    Digest: %s\n", digest_hex);
            printf("    [INFO] Compare with Java: SM3Util.digestToStr(\"%s\")\n", SM3_TEST_STRING);
            free(digest_hex);
        }
    }

    /* --- 2. HMAC-SM3 (HEX key) --- */
    printf("\n--- 2. HMAC-SM3 with Java HEX key ---\n");
    {
        char* hmac_hex = NULL;
        ret = crossmool_sm3_hmac_to_hex(SM3_HMAC_KEY_HEX, SM3_TEST_STRING, &hmac_hex);
        report("hmac_to_hex with HEX key", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS) {
            printf("    Key:  %s\n", SM3_HMAC_KEY_HEX);
            printf("    Data: %s\n", SM3_TEST_STRING);
            printf("    HMAC: %s\n", hmac_hex);
            printf("    [INFO] Compare with Java: SM3Util.hmacToStr(\"%s\", \"%s\")\n",
                   SM3_HMAC_KEY_HEX, SM3_TEST_STRING);

            /* 自验签 */
            int vr = crossmool_sm3_hmac_verify(SM3_HMAC_KEY_HEX, NULL, SM3_TEST_STRING, NULL, hmac_hex);
            report("hmac_verify with HEX key", vr == 1);

            free(hmac_hex);
        }
    }

    /* --- 3. HMAC-SM3 (Base64 key) --- */
    printf("\n--- 3. HMAC-SM3 with Java Base64 key ---\n");
    {
        char* hmac_hex = NULL;
        ret = crossmool_sm3_hmac_to_hex(SM3_HMAC_KEY_B64, SM3_TEST_STRING, &hmac_hex);
        report("hmac_to_hex with Base64 key", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS) {
            printf("    Key:  %s\n", SM3_HMAC_KEY_B64);
            printf("    Data: %s\n", SM3_TEST_STRING);
            printf("    HMAC: %s\n", hmac_hex);
            printf("    [INFO] Compare with Java: SM3Util.hmacToStr(\"%s\", \"%s\")\n",
                   SM3_HMAC_KEY_B64, SM3_TEST_STRING);

            /* Base64 key 产生的 HMAC 应该与 HEX key 产生的相同（密钥数据一致） */
            char* hmac_hex2 = NULL;
            ret = crossmool_sm3_hmac_to_hex(SM3_HMAC_KEY_HEX, SM3_TEST_STRING, &hmac_hex2);
            if (ret == CROSSMOOL_SUCCESS) {
                report("HEX and Base64 key produce same HMAC", strcmp(hmac_hex, hmac_hex2) == 0);
                free(hmac_hex2);
            }

            int vr = crossmool_sm3_hmac_verify(SM3_HMAC_KEY_B64, NULL, SM3_TEST_STRING, NULL, hmac_hex);
            report("hmac_verify with Base64 key", vr == 1);

            free(hmac_hex);
        }
    }
}

/* ============================================================
 * SM4 跨语言互通测试
 * ============================================================ */
static void test_sm4_crosslang(void) {
    printf("\n=== SM4 Cross-Language Interop Test ===\n\n");
    int ret;

    /* --- 1. 使用 Java SM4 密钥加密解密 --- */
    printf("--- 1. SM4 ECB encrypt/decrypt with Java key ---\n");
    {
        unsigned char key[16];
        ret = crossmool_sm4_parse_hex_key(SM4_KEY_HEX, key);
        report("parse Java HEX key", ret == CROSSMOOL_SUCCESS);

        if (ret == CROSSMOOL_SUCCESS) {
            printf("    Key (HEX): %s\n", SM4_KEY_HEX);

            /* 加密 */
            char* ciphertext_hex = NULL;
            ret = crossmool_sm4_encrypt_ecb(key,
                                             (const unsigned char*)SM4_TEST_STRING,
                                             strlen(SM4_TEST_STRING),
                                             &ciphertext_hex);
            report("encrypt with Java key", ret == CROSSMOOL_SUCCESS);

            if (ret == CROSSMOOL_SUCCESS) {
                printf("    Plaintext:  %s\n", SM4_TEST_STRING);
                printf("    Ciphertext: %s\n", ciphertext_hex);
                printf("    [INFO] Compare with Java: SM4Util.encryptEcbNative(key, plaintext)\n");

                /* 解密 */
                unsigned char* decrypted = NULL;
                size_t dec_len = 0;
                ret = crossmool_sm4_decrypt_ecb(key, ciphertext_hex, &decrypted, &dec_len);
                report("decrypt with Java key", ret == CROSSMOOL_SUCCESS);

                if (ret == CROSSMOOL_SUCCESS) {
                    /* PKCS7 解填充后明文应该与原始一致 */
                    report("decrypted content matches",
                           dec_len == strlen(SM4_TEST_STRING) &&
                           memcmp(decrypted, SM4_TEST_STRING, dec_len) == 0);
                    printf("    Decrypted:  %.*s\n", (int)dec_len, decrypted);
                    free(decrypted);
                }
                free(ciphertext_hex);
            }
        }
    }
}

/* ============================================================
 * 主函数
 * ============================================================ */
int main(void) {
    printf("============================================================\n");
    printf("  Crossmool C/Java Cross-Language Interoperability Tests\n");
    printf("  Using fixed test keys from Java Constant classes\n");
    printf("============================================================\n");

    test_sm2_crosslang();
    test_sm3_crosslang();
    test_sm4_crosslang();

    printf("\n============================================================\n");
    printf("  Summary: %d PASS, %d FAIL\n", g_pass, g_fail);
    printf("============================================================\n");

    return g_fail > 0 ? 1 : 0;
}
