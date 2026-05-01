#include "crossmool_sm2.h"
#include "crossmool_util.h"
/* 禁用 GmSSL 的 error_print()/fprintf(stderr) 宏，
 * 避免 DLL 与 EXE 使用不同 CRT 实例时 stderr 为 NULL 导致崩溃 */
#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// SM2 密钥长度
#define SM2_PRIVATE_KEY_SIZE              32
#define SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE  65
#define SM2_SIGNATURE_MAX_SIZE            72

/* ====================================================
 * 内部辅助：解码公钥字节 → SM2_POINT
 * 支持：
 *   - 65 字节非压缩格式（04||x||y）
 *   - 64 字节裸格式（x||y）
 *   - X.509 SubjectPublicKeyInfo DER/ASN.1 编码（Java BouncyCastle 默认输出）
 * ==================================================== */
static int decode_public_key_to_point(const char* public_key, SM2_POINT* point)
{
    unsigned char* buf = NULL;
    size_t buf_len = 0;
    int ret;

    if (crossmool_is_hex_string(public_key)) {
        ret = crossmool_hex_decode(public_key, &buf, &buf_len);
    } else {
        ret = crossmool_base64_decode(public_key, &buf, &buf_len);
    }
    if (ret != CROSSMOOL_SUCCESS) return CROSSMOOL_ERR_KEY_INVALID;

    if (buf_len == SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE && buf[0] == 0x04) {
        /* 65 字节非压缩格式：04 || x[32] || y[32] */
        memcpy(point->x, buf + 1, 32);
        memcpy(point->y, buf + 1 + 32, 32);
        free(buf);
        return CROSSMOOL_SUCCESS;
    } else if (buf_len == 64) {
        /* 64 字节裸格式：x[32] || y[32] */
        memcpy(point->x, buf, 32);
        memcpy(point->y, buf + 32, 32);
        free(buf);
        return CROSSMOOL_SUCCESS;
    } else if (buf_len > 65) {
        /* 可能是 X.509 SubjectPublicKeyInfo DER 编码，尝试用 GmSSL 解析 */
        const unsigned char* p = buf;
        size_t len = buf_len;
        SM2_KEY sm2_key;
        memset(&sm2_key, 0, sizeof(sm2_key));
        int gmssl_ret = sm2_public_key_info_from_der(&sm2_key, &p, &len);
        if (gmssl_ret == 1) {
            /* 成功从 X.509 DER 提取公钥点 */
            memcpy(point, &sm2_key.public_key, sizeof(SM2_POINT));
            free(buf);
            return CROSSMOOL_SUCCESS;
        }
        /* 尝试 ECPrivateKey DER 格式（ECDSA 签名用公钥） */
        p = buf;
        len = buf_len;
        memset(&sm2_key, 0, sizeof(sm2_key));
        gmssl_ret = sm2_private_key_from_der(&sm2_key, &p, &len);
        if (gmssl_ret == 1) {
            memcpy(point, &sm2_key.public_key, sizeof(SM2_POINT));
            free(buf);
            return CROSSMOOL_SUCCESS;
        }
        free(buf);
        return CROSSMOOL_ERR_KEY_INVALID;
    } else {
        free(buf);
        return CROSSMOOL_ERR_KEY_INVALID;
    }
}

/* 保留字节数组版本，仅供 keypair_to_hex/base64 使用 */
static int decode_public_key(const char* public_key,
                              unsigned char* out_bytes,
                              size_t* out_len)
{
    unsigned char* buf = NULL;
    size_t buf_len = 0;
    int ret;

    if (crossmool_is_hex_string(public_key)) {
        ret = crossmool_hex_decode(public_key, &buf, &buf_len);
    } else {
        ret = crossmool_base64_decode(public_key, &buf, &buf_len);
    }
    if (ret != CROSSMOOL_SUCCESS) return CROSSMOOL_ERR_KEY_INVALID;
    if (buf_len != SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE) {
        free(buf);
        return CROSSMOOL_ERR_KEY_INVALID;
    }
    memcpy(out_bytes, buf, buf_len);
    *out_len = buf_len;
    free(buf);
    return CROSSMOOL_SUCCESS;
}

static int decode_private_key(const char* private_key,
                               unsigned char* out_bytes,
                               size_t* out_len)
{
    unsigned char* buf = NULL;
    size_t buf_len = 0;
    int ret;

    if (crossmool_is_hex_string(private_key)) {
        ret = crossmool_hex_decode(private_key, &buf, &buf_len);
    } else {
        ret = crossmool_base64_decode(private_key, &buf, &buf_len);
    }
    if (ret != CROSSMOOL_SUCCESS) return CROSSMOOL_ERR_KEY_INVALID;

    if (buf_len == SM2_PRIVATE_KEY_SIZE) {
        /* 32 字节原始私钥 */
        memcpy(out_bytes, buf, buf_len);
        *out_len = buf_len;
        free(buf);
        return CROSSMOOL_SUCCESS;
    } else if (buf_len > 32) {
        /* 可能是 PKCS#8 PrivateKeyInfo DER 编码，尝试用 GmSSL 解析 */
        const unsigned char* p = buf;
        size_t len = buf_len;
        const unsigned char* attrs = NULL;
        size_t attrslen = 0;
        SM2_KEY sm2_key;
        memset(&sm2_key, 0, sizeof(sm2_key));
        int gmssl_ret = sm2_private_key_info_from_der(&sm2_key, &attrs, &attrslen, &p, &len);
        if (gmssl_ret == 1) {
            /* 成功从 PKCS#8 DER 提取私钥（32 字节） */
            memcpy(out_bytes, sm2_key.private_key, SM2_PRIVATE_KEY_SIZE);
            *out_len = SM2_PRIVATE_KEY_SIZE;
            free(buf);
            return CROSSMOOL_SUCCESS;
        }
        free(buf);
        return CROSSMOOL_ERR_KEY_INVALID;
    } else {
        free(buf);
        return CROSSMOOL_ERR_KEY_INVALID;
    }
}

/* ====================================================
 * 密钥生成
 * ==================================================== */

int crossmool_sm2_generate_keypair(crossmool_sm2_keypair_t** keypair)
{
    if (keypair == NULL) return CROSSMOOL_ERR_INVALID_PARAM;

    crossmool_sm2_keypair_t* kp =
        (crossmool_sm2_keypair_t*)calloc(1, sizeof(crossmool_sm2_keypair_t));
    if (kp == NULL) return CROSSMOOL_ERR_MEMORY_ALLOC;

    SM2_KEY key;
    if (sm2_key_generate(&key) < 0) {
        free(kp);
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }

    /* 默认存储 HEX 格式 */
    int ret = crossmool_hex_encode(key.private_key, SM2_PRIVATE_KEY_SIZE,
                                   &kp->private_key);
    if (ret != CROSSMOOL_SUCCESS) { free(kp); return ret; }

    unsigned char pub_bytes[SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    sm2_point_to_uncompressed_octets(&key.public_key, pub_bytes);
    ret = crossmool_hex_encode(pub_bytes, SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE,
                               &kp->public_key);
    if (ret != CROSSMOOL_SUCCESS) {
        free(kp->private_key);
        free(kp);
        return ret;
    }

    /* 同时填充 _hex 字段（复制一份） */
    kp->private_key_hex = _strdup(kp->private_key);
    kp->public_key_hex  = _strdup(kp->public_key);
    if (!kp->private_key_hex || !kp->public_key_hex) {
        crossmool_sm2_keypair_free(kp);
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }

    *keypair = kp;
    return CROSSMOOL_SUCCESS;
}

int crossmool_sm2_keypair_to_hex(crossmool_sm2_keypair_t* keypair)
{
    if (keypair == NULL) return CROSSMOOL_ERR_INVALID_PARAM;

    /* private_key 字段已存储（可能是 HEX 或 Base64），
       统一解码再重新编码为 HEX */
    unsigned char priv_bytes[SM2_PRIVATE_KEY_SIZE];
    unsigned char pub_bytes[SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    size_t len = 0;
    int ret;

    ret = decode_private_key(keypair->private_key, priv_bytes, &len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = decode_public_key(keypair->public_key, pub_bytes, &len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    if (keypair->private_key_hex) { free(keypair->private_key_hex); keypair->private_key_hex = NULL; }
    if (keypair->public_key_hex)  { free(keypair->public_key_hex);  keypair->public_key_hex  = NULL; }

    ret = crossmool_hex_encode(priv_bytes, SM2_PRIVATE_KEY_SIZE, &keypair->private_key_hex);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_hex_encode(pub_bytes, SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE, &keypair->public_key_hex);
    return ret;
}

int crossmool_sm2_keypair_to_base64(crossmool_sm2_keypair_t* keypair)
{
    if (keypair == NULL) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char priv_bytes[SM2_PRIVATE_KEY_SIZE];
    unsigned char pub_bytes[SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    size_t len = 0;
    int ret;

    ret = decode_private_key(keypair->private_key, priv_bytes, &len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = decode_public_key(keypair->public_key, pub_bytes, &len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    if (keypair->private_key_base64) { free(keypair->private_key_base64); keypair->private_key_base64 = NULL; }
    if (keypair->public_key_base64)  { free(keypair->public_key_base64);  keypair->public_key_base64  = NULL; }

    ret = crossmool_base64_encode(priv_bytes, SM2_PRIVATE_KEY_SIZE, &keypair->private_key_base64);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_base64_encode(pub_bytes, SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE, &keypair->public_key_base64);
    return ret;
}

int crossmool_sm2_generate_keypair_base64(crossmool_sm2_keypair_t* keypair)
{
    if (keypair == NULL) return CROSSMOOL_ERR_INVALID_PARAM;
    SM2_KEY key;
    int ret;
    if (sm2_key_generate(&key) < 0) return CROSSMOOL_ERR_ENCRYPT_DECRYPT;

    ret = crossmool_base64_encode(key.private_key, SM2_PRIVATE_KEY_SIZE, &keypair->private_key);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    unsigned char pub_bytes[SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    sm2_point_to_uncompressed_octets(&key.public_key, pub_bytes);
    ret = crossmool_base64_encode(pub_bytes, SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE, &keypair->public_key);
    if (ret != CROSSMOOL_SUCCESS) {
        free(keypair->private_key); keypair->private_key = NULL;
    }
    return ret;
}

int crossmool_sm2_generate_keypair_hex(crossmool_sm2_keypair_t* keypair)
{
    if (keypair == NULL) return CROSSMOOL_ERR_INVALID_PARAM;
    SM2_KEY key;
    int ret;
    if (sm2_key_generate(&key) < 0) return CROSSMOOL_ERR_ENCRYPT_DECRYPT;

    ret = crossmool_hex_encode(key.private_key, SM2_PRIVATE_KEY_SIZE, &keypair->private_key);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    unsigned char pub_bytes[SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE];
    sm2_point_to_uncompressed_octets(&key.public_key, pub_bytes);
    ret = crossmool_hex_encode(pub_bytes, SM2_PUBLIC_KEY_UNCOMPRESSED_SIZE, &keypair->public_key);
    if (ret != CROSSMOOL_SUCCESS) {
        free(keypair->private_key); keypair->private_key = NULL;
    }
    return ret;
}

void crossmool_sm2_keypair_free(crossmool_sm2_keypair_t* keypair)
{
    if (keypair == NULL) return;
    if (keypair->private_key)      { free(keypair->private_key);      keypair->private_key      = NULL; }
    if (keypair->public_key)       { free(keypair->public_key);       keypair->public_key       = NULL; }
    if (keypair->private_key_hex)  { free(keypair->private_key_hex);  keypair->private_key_hex  = NULL; }
    if (keypair->public_key_hex)   { free(keypair->public_key_hex);   keypair->public_key_hex   = NULL; }
    if (keypair->private_key_base64){ free(keypair->private_key_base64); keypair->private_key_base64 = NULL; }
    if (keypair->public_key_base64) { free(keypair->public_key_base64);  keypair->public_key_base64  = NULL; }
    free(keypair);
}

/* ====================================================
 * 内部核心加密（字节数组输入/输出）
 * ==================================================== */
static int sm2_encrypt_core(const unsigned char* content, size_t content_len,
                             const char* public_key,
                             unsigned char** ciphertext, size_t* ciphertext_len)
{
    SM2_KEY key;
    SM2_POINT tmp_pub;
    unsigned char* buf = NULL;
    size_t max_len;
    size_t actual_len = 0;
    int ret;

    memset(&key, 0, sizeof(SM2_KEY));
    memset(&tmp_pub, 0, sizeof(SM2_POINT));
    ret = decode_public_key_to_point(public_key, &tmp_pub);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    /* 用 sm2_key_set_public_key 校验并设置公钥（不需要私钥） */
    if (sm2_key_set_public_key(&key, &tmp_pub) < 0)
        return CROSSMOOL_ERR_KEY_INVALID;

    max_len = content_len + 1024;
    buf = (unsigned char*)malloc(max_len);
    if (!buf) return CROSSMOOL_ERR_MEMORY_ALLOC;

    ret = sm2_encrypt(&key, content, content_len, buf, &actual_len);
    if (ret < 0) { free(buf); return CROSSMOOL_ERR_ENCRYPT_DECRYPT; }

    *ciphertext = buf;
    *ciphertext_len = actual_len;
    return CROSSMOOL_SUCCESS;
}

/* ====================================================
 * 内部核心解密
 * ==================================================== */
static int sm2_decrypt_core(const char* ciphertext_str, const char* private_key,
                             unsigned char** plaintext, size_t* plaintext_len)
{
    unsigned char priv_bytes[SM2_PRIVATE_KEY_SIZE];
    size_t priv_len = 0;
    unsigned char* ct_bytes = NULL;
    size_t ct_len = 0;
    SM2_KEY key;
    unsigned char* buf = NULL;
    size_t actual_len = 0;
    int ret;

    ret = decode_private_key(private_key, priv_bytes, &priv_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    if (crossmool_is_hex_string(ciphertext_str))
        ret = crossmool_hex_decode(ciphertext_str, &ct_bytes, &ct_len);
    else
        ret = crossmool_base64_decode(ciphertext_str, &ct_bytes, &ct_len);

    if (ret != CROSSMOOL_SUCCESS) return CROSSMOOL_ERR_FORMAT_CONVERSION;

    if (sm2_key_set_private_key(&key, priv_bytes) < 0) {
        free(ct_bytes);
        return CROSSMOOL_ERR_KEY_INVALID;
    }

    buf = (unsigned char*)malloc(ct_len);
    if (!buf) { free(ct_bytes); return CROSSMOOL_ERR_MEMORY_ALLOC; }

    ret = sm2_decrypt(&key, ct_bytes, ct_len, buf, &actual_len);
    free(ct_bytes);
    if (ret < 0) { free(buf); return CROSSMOOL_ERR_ENCRYPT_DECRYPT; }

    *plaintext = buf;
    *plaintext_len = actual_len;
    return CROSSMOOL_SUCCESS;
}

/* ====================================================
 * 内部核心签名（使用 SM3-with-ID，与 Java 保持一致）
 * Java 使用的 USER_ID 为 "1234567812345678"
 * ==================================================== */
static int sm2_sign_core(const unsigned char* content, size_t content_len,
                          const char* private_key,
                          unsigned char** signature, size_t* sig_len)
{
    unsigned char priv_bytes[SM2_PRIVATE_KEY_SIZE];
    size_t priv_len = 0;
    SM2_KEY key;
    SM2_SIGN_CTX ctx;
    unsigned char sig_buf[SM2_SIGNATURE_MAX_SIZE];
    size_t sig_buf_len = 0;
    int ret;

    ret = decode_private_key(private_key, priv_bytes, &priv_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    if (sm2_key_set_private_key(&key, priv_bytes) < 0) return CROSSMOOL_ERR_KEY_INVALID;

    /* 使用 SM3-with-ID 进行签名，USER_ID 与 Java 保持一致 */
    ret = sm2_sign_init(&ctx, &key, "1234567812345678", 16);
    if (ret < 0) return CROSSMOOL_ERR_SIGN_VERIFY;

    ret = sm2_sign_update(&ctx, content, content_len);
    if (ret < 0) return CROSSMOOL_ERR_SIGN_VERIFY;

    ret = sm2_sign_finish(&ctx, sig_buf, &sig_buf_len);
    if (ret < 0) return CROSSMOOL_ERR_SIGN_VERIFY;

    *signature = (unsigned char*)malloc(sig_buf_len);
    if (!*signature) return CROSSMOOL_ERR_MEMORY_ALLOC;
    memcpy(*signature, sig_buf, sig_buf_len);
    *sig_len = sig_buf_len;
    return CROSSMOOL_SUCCESS;
}

/* ====================================================
 * 内部核心验签（使用 SM3-with-ID，与 Java 保持一致）
 * Java 使用的 USER_ID 为 "1234567812345678"
 * ==================================================== */
static int sm2_verify_core(const unsigned char* content, size_t content_len,
                             const char* signature_str, const char* public_key)
{
    unsigned char* sig_bytes = NULL;
    size_t sig_len = 0;
    SM2_KEY key;
    SM2_POINT tmp_pub;
    SM2_SIGN_CTX ctx;
    int ret;

    memset(&key, 0, sizeof(SM2_KEY));
    memset(&tmp_pub, 0, sizeof(SM2_POINT));
    ret = decode_public_key_to_point(public_key, &tmp_pub);
    if (ret != CROSSMOOL_SUCCESS) return CROSSMOOL_ERR_KEY_INVALID;

    if (crossmool_is_hex_string(signature_str))
        ret = crossmool_hex_decode(signature_str, &sig_bytes, &sig_len);
    else
        ret = crossmool_base64_decode(signature_str, &sig_bytes, &sig_len);

    if (ret != CROSSMOOL_SUCCESS) return CROSSMOOL_ERR_FORMAT_CONVERSION;

    /* 设置公钥（同时验证点是否在曲线上） */
    if (sm2_key_set_public_key(&key, &tmp_pub) < 0) {
        free(sig_bytes);
        return CROSSMOOL_ERR_KEY_INVALID;
    }

    /* 使用 SM3-with-ID 进行验签，USER_ID 与 Java 保持一致 */
    ret = sm2_verify_init(&ctx, &key, "1234567812345678", 16);
    if (ret < 0) {
        free(sig_bytes);
        return CROSSMOOL_ERR_SIGN_VERIFY;
    }

    ret = sm2_verify_update(&ctx, content, content_len);
    if (ret < 0) {
        free(sig_bytes);
        return CROSSMOOL_ERR_SIGN_VERIFY;
    }

    ret = sm2_verify_finish(&ctx, sig_bytes, sig_len);
    free(sig_bytes);

    /* sm2_verify_finish: 1 = success, <= 0 = failure */
    if (ret == 1) return 1;  /* 验签成功 */
    return 0;                 /* 验签失败 */
}

/* ====================================================
 * 公开 API 实现（简化字符串接口）
 * ==================================================== */

int crossmool_sm2_encrypt(
    const char* content, const char* charset, const char* public_key,
    char** ciphertext_hex)
{
    if (!content || !public_key || !ciphertext_hex) return CROSSMOOL_ERR_INVALID_PARAM;
    (void)charset;

    unsigned char* ct = NULL;
    size_t ct_len = 0;
    int ret = sm2_encrypt_core((const unsigned char*)content, strlen(content),
                               public_key, &ct, &ct_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_hex_encode(ct, ct_len, ciphertext_hex);
    free(ct);
    return ret;
}

int crossmool_sm2_decrypt(
    const char* ciphertext, const char* private_key, const char* charset,
    char** plaintext_str)
{
    if (!ciphertext || !private_key || !plaintext_str) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* pt = NULL;
    size_t pt_len = 0;
    int ret = sm2_decrypt_core(ciphertext, private_key, &pt, &pt_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    ret = crossmool_bytes_to_string(pt, pt_len, charset, plaintext_str);
    free(pt);
    return ret;
}

int crossmool_sm2_sign(
    const char* content, const char* charset, const char* private_key,
    char** signature_hex)
{
    if (!content || !private_key || !signature_hex) return CROSSMOOL_ERR_INVALID_PARAM;
    (void)charset;

    unsigned char* sig = NULL;
    size_t sig_len = 0;
    int ret = sm2_sign_core((const unsigned char*)content, strlen(content),
                            private_key, &sig, &sig_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_hex_encode(sig, sig_len, signature_hex);
    free(sig);
    return ret;
}

int crossmool_sm2_verify(
    const char* content, const char* charset, const char* signature,
    const char* public_key)
{
    if (!content || !signature || !public_key) return CROSSMOOL_ERR_INVALID_PARAM;
    (void)charset;

    return sm2_verify_core((const unsigned char*)content, strlen(content),
                           signature, public_key);
}

/* ====================================================
 * 字节数组接口
 * ==================================================== */

int crossmool_sm2_encrypt_bytes(
    const unsigned char* content, size_t content_len, const char* public_key,
    unsigned char** ciphertext, size_t* ciphertext_len)
{
    if (!content || !public_key || !ciphertext || !ciphertext_len)
        return CROSSMOOL_ERR_INVALID_PARAM;
    return sm2_encrypt_core(content, content_len, public_key, ciphertext, ciphertext_len);
}

int crossmool_sm2_encrypt_to_hex(
    const unsigned char* content, size_t content_len, const char* charset,
    const char* public_key, char** ciphertext_hex)
{
    (void)charset;
    if (!content || !public_key || !ciphertext_hex) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* ct = NULL; size_t ct_len = 0;
    int ret = sm2_encrypt_core(content, content_len, public_key, &ct, &ct_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_hex_encode(ct, ct_len, ciphertext_hex);
    free(ct);
    return ret;
}

int crossmool_sm2_encrypt_to_base64(
    const unsigned char* content, size_t content_len, const char* charset,
    const char* public_key, char** ciphertext_base64)
{
    (void)charset;
    if (!content || !public_key || !ciphertext_base64) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* ct = NULL; size_t ct_len = 0;
    int ret = sm2_encrypt_core(content, content_len, public_key, &ct, &ct_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_base64_encode(ct, ct_len, ciphertext_base64);
    free(ct);
    return ret;
}

int crossmool_sm2_decrypt_bytes(
    const char* ciphertext, const char* private_key,
    unsigned char** plaintext, size_t* plaintext_len)
{
    if (!ciphertext || !private_key || !plaintext || !plaintext_len)
        return CROSSMOOL_ERR_INVALID_PARAM;
    return sm2_decrypt_core(ciphertext, private_key, plaintext, plaintext_len);
}

int crossmool_sm2_decrypt_to_string(
    const char* ciphertext, const char* private_key, const char* charset,
    char** plaintext_str)
{
    unsigned char* pt = NULL; size_t pt_len = 0;
    int ret = sm2_decrypt_core(ciphertext, private_key, &pt, &pt_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_bytes_to_string(pt, pt_len, charset, plaintext_str);
    free(pt);
    return ret;
}

int crossmool_sm2_sign_bytes(
    const unsigned char* content, size_t content_len, const char* private_key,
    unsigned char** signature, size_t* signature_len)
{
    if (!content || !private_key || !signature || !signature_len)
        return CROSSMOOL_ERR_INVALID_PARAM;
    return sm2_sign_core(content, content_len, private_key, signature, signature_len);
}

int crossmool_sm2_sign_to_hex(
    const unsigned char* content, size_t content_len, const char* charset,
    const char* private_key, char** signature_hex)
{
    (void)charset;
    if (!content || !private_key || !signature_hex) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* sig = NULL; size_t sig_len = 0;
    int ret = sm2_sign_core(content, content_len, private_key, &sig, &sig_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_hex_encode(sig, sig_len, signature_hex);
    free(sig);
    return ret;
}

int crossmool_sm2_sign_to_base64(
    const unsigned char* content, size_t content_len, const char* charset,
    const char* private_key, char** signature_base64)
{
    (void)charset;
    if (!content || !private_key || !signature_base64) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* sig = NULL; size_t sig_len = 0;
    int ret = sm2_sign_core(content, content_len, private_key, &sig, &sig_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    ret = crossmool_base64_encode(sig, sig_len, signature_base64);
    free(sig);
    return ret;
}

int crossmool_sm2_verify_bytes(
    const unsigned char* content, size_t content_len,
    const char* signature, const char* public_key)
{
    if (!content || !signature || !public_key) return CROSSMOOL_ERR_INVALID_PARAM;
    return sm2_verify_core(content, content_len, signature, public_key);
}

/* ====================================================
 * 组合接口
 * ==================================================== */

int crossmool_sm2_encrypt_sign(
    const char* content, const char* charset,
    const char* enc_public_key, const char* sign_private_key,
    crossmool_sm2_cipher_sig_pair_t** result)
{
    if (!content || !enc_public_key || !sign_private_key || !result)
        return CROSSMOOL_ERR_INVALID_PARAM;

    crossmool_sm2_cipher_sig_pair_t* pair =
        (crossmool_sm2_cipher_sig_pair_t*)calloc(1, sizeof(crossmool_sm2_cipher_sig_pair_t));
    if (!pair) return CROSSMOOL_ERR_MEMORY_ALLOC;

    int ret = crossmool_sm2_encrypt(content, charset, enc_public_key, &pair->ciphertext_hex);
    if (ret != CROSSMOOL_SUCCESS) { free(pair); return ret; }
    pair->ciphertext = _strdup(pair->ciphertext_hex);

    ret = crossmool_sm2_sign(content, charset, sign_private_key, &pair->signature_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        crossmool_sm2_cipher_sig_pair_free(pair);
        return ret;
    }
    pair->signature = _strdup(pair->signature_hex);

    *result = pair;
    return CROSSMOOL_SUCCESS;
}

int crossmool_sm2_verify_decrypt(
    const char* ciphertext, const char* signature,
    const char* sign_public_key, const char* dec_private_key,
    const char* charset, char** plaintext)
{
    if (!ciphertext || !signature || !sign_public_key || !dec_private_key || !plaintext)
        return CROSSMOOL_ERR_INVALID_PARAM;

    /* 先解密，获得原文 */
    unsigned char* pt = NULL; size_t pt_len = 0;
    int ret = sm2_decrypt_core(ciphertext, dec_private_key, &pt, &pt_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    /* 验签 */
    ret = sm2_verify_core(pt, pt_len, signature, sign_public_key);
    if (ret != 1) {
        free(pt);
        return (ret < 0) ? ret : CROSSMOOL_ERR_SIGN_VERIFY;
    }

    /* 转换为字符串 */
    ret = crossmool_bytes_to_string(pt, pt_len, charset, plaintext);
    free(pt);
    return ret;
}

int crossmool_sm2_encrypt_sign_ex(
    const unsigned char* content, size_t content_len, const char* charset,
    const char* enc_public_key, const char* sign_private_key,
    int to_base64, crossmool_sm2_cipher_sig_pair_t* result)
{
    if (!content || !enc_public_key || !sign_private_key || !result)
        return CROSSMOOL_ERR_INVALID_PARAM;
    (void)charset;

    int ret;
    if (to_base64) {
        ret = crossmool_sm2_encrypt_to_base64(content, content_len, charset,
                                               enc_public_key, &result->ciphertext);
    } else {
        ret = crossmool_sm2_encrypt_to_hex(content, content_len, charset,
                                            enc_public_key, &result->ciphertext);
    }
    if (ret != CROSSMOOL_SUCCESS) return ret;

    if (to_base64) {
        ret = crossmool_sm2_sign_to_base64(content, content_len, charset,
                                            sign_private_key, &result->signature);
    } else {
        ret = crossmool_sm2_sign_to_hex(content, content_len, charset,
                                         sign_private_key, &result->signature);
    }
    if (ret != CROSSMOOL_SUCCESS) {
        free(result->ciphertext); result->ciphertext = NULL;
    }
    return ret;
}

void crossmool_sm2_cipher_sig_pair_free(crossmool_sm2_cipher_sig_pair_t* pair)
{
    if (!pair) return;
    if (pair->ciphertext)        { free(pair->ciphertext);        pair->ciphertext        = NULL; }
    if (pair->signature)         { free(pair->signature);         pair->signature         = NULL; }
    if (pair->ciphertext_hex)    { free(pair->ciphertext_hex);    pair->ciphertext_hex    = NULL; }
    if (pair->signature_hex)     { free(pair->signature_hex);     pair->signature_hex     = NULL; }
    if (pair->ciphertext_base64) { free(pair->ciphertext_base64); pair->ciphertext_base64 = NULL; }
    if (pair->signature_base64)  { free(pair->signature_base64);  pair->signature_base64  = NULL; }
    free(pair);
}
