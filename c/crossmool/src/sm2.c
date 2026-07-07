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

    /* FIX-020: 将 GmSSL 的 DER 输出转换为 C1C3C2 格式，以支持跨语言互通 */
    unsigned char* raw_ct = NULL;
    size_t raw_ct_len = 0;
    int conv_ret = sm2_der_to_raw_c1c3c2(buf, actual_len, &raw_ct, &raw_ct_len);
    free(buf);
    if (conv_ret != 0) {
        /* 如果转换失败，回退到原始 DER 格式（兼容旧版本） */
        unsigned char* fallback = (unsigned char*)malloc(actual_len);
        if (!fallback) return CROSSMOOL_ERR_MEMORY_ALLOC;
        /* Need to re-encrypt since we freed buf */
        ret = sm2_encrypt(&key, content, content_len, fallback, &actual_len);
        if (ret < 0) { free(fallback); return CROSSMOOL_ERR_ENCRYPT_DECRYPT; }
        *ciphertext = fallback;
        *ciphertext_len = actual_len;
    } else {
        *ciphertext = raw_ct;
        *ciphertext_len = raw_ct_len;
    }
    return CROSSMOOL_SUCCESS;
}

/* ====================================================
 * 内部辅助：将 Java/BouncyCastle 的 RAW 格式密文转换为 GmSSL 的 DER SEQUENCE 格式
 *
 * Java SM2Engine(C1C3C2) 输出格式: 04 || x[32] || y[32] || C3[32] || C2[N]
 * GmSSL sm2_decrypt 期望格式:
 *   SM2Cipher ::= SEQUENCE {
 *       XCoordinate  INTEGER,
 *       YCoordinate  INTEGER,
 *       HASH         OCTET STRING SIZE(32),
 *       CipherText   OCTET STRING }
 *
 * 输出 der_out 由本函数 malloc，调用方负责 free。
 * ==================================================== */
static int sm2_raw_c1c3c2_to_der(const unsigned char* raw, size_t raw_len,
                                  unsigned char** der_out, size_t* der_len)
{
    if (raw_len < 1 + 32 + 32 + 32 + 1) return -1; /* 至少 04+x+y+c3+1byte_c2 */
    if (raw[0] != 0x04) return -1;                  /* 必须是非压缩点标记 */

    const unsigned char* x  = raw + 1;
    const unsigned char* y  = raw + 1 + 32;
    const unsigned char* c3 = raw + 1 + 64;
    const unsigned char* c2 = raw + 1 + 96;
    size_t c2_len = raw_len - (1 + 32 + 32 + 32);

    /* --- 编码 INTEGER x --- */
    /* 跳过前导零，若最高位为1则加 0x00 前缀 */
    size_t xi = 0;
    while (xi < 31 && x[xi] == 0x00) xi++;
    const unsigned char* xv = x + xi;
    size_t xv_len = 32 - xi;
    int x_pad = (xv[0] & 0x80) ? 1 : 0;
    size_t int_x_len = 2 + x_pad + xv_len; /* tag + len + [pad] + val */

    /* --- 编码 INTEGER y --- */
    size_t yi = 0;
    while (yi < 31 && y[yi] == 0x00) yi++;
    const unsigned char* yv = y + yi;
    size_t yv_len = 32 - yi;
    int y_pad = (yv[0] & 0x80) ? 1 : 0;
    size_t int_y_len = 2 + y_pad + yv_len;

    /* --- 编码 OCTET STRING c3 (固定 32 字节) --- */
    size_t oct_c3_len = 2 + 32;

    /* --- 编码 OCTET STRING c2 --- */
    size_t oct_c2_hdr = 2; /* tag + len (1 byte 或 2 bytes) */
    if (c2_len >= 128) oct_c2_hdr = 3; /* 长格式: 04 81 NN */
    if (c2_len >= 256) oct_c2_hdr = 4; /* 长格式: 04 82 HH LL */
    size_t oct_c2_len = oct_c2_hdr + c2_len;

    /* --- 计算 SEQUENCE 内部长度 --- */
    size_t inner_len = int_x_len + int_y_len + oct_c3_len + oct_c2_len;

    /* --- 计算 SEQUENCE 头部长度 --- */
    size_t seq_hdr = 2;
    if (inner_len >= 128) seq_hdr = 3;  /* 30 81 NN */
    if (inner_len >= 256) seq_hdr = 4;  /* 30 82 HH LL */

    size_t total = seq_hdr + inner_len;
    unsigned char* out = (unsigned char*)malloc(total);
    if (!out) return -1;

    unsigned char* p = out;

    /* SEQUENCE header */
    *p++ = 0x30;
    if (inner_len < 128) {
        *p++ = (unsigned char)inner_len;
    } else if (inner_len < 256) {
        *p++ = 0x81; *p++ = (unsigned char)inner_len;
    } else {
        *p++ = 0x82;
        *p++ = (unsigned char)(inner_len >> 8);
        *p++ = (unsigned char)(inner_len & 0xff);
    }

    /* INTEGER x */
    *p++ = 0x02;
    *p++ = (unsigned char)(x_pad + xv_len);
    if (x_pad) *p++ = 0x00;
    memcpy(p, xv, xv_len); p += xv_len;

    /* INTEGER y */
    *p++ = 0x02;
    *p++ = (unsigned char)(y_pad + yv_len);
    if (y_pad) *p++ = 0x00;
    memcpy(p, yv, yv_len); p += yv_len;

    /* OCTET STRING c3 (32 bytes) */
    *p++ = 0x04; *p++ = 32;
    memcpy(p, c3, 32); p += 32;

    /* OCTET STRING c2 */
    *p++ = 0x04;
    if (c2_len < 128) {
        *p++ = (unsigned char)c2_len;
    } else if (c2_len < 256) {
        *p++ = 0x81; *p++ = (unsigned char)c2_len;
    } else {
        *p++ = 0x82;
        *p++ = (unsigned char)(c2_len >> 8);
        *p++ = (unsigned char)(c2_len & 0xff);
    }
    memcpy(p, c2, c2_len);

    *der_out = out;
    *der_len = total;
    return 0;
}

/* ====================================================
 * 内部辅助：将 GmSSL 的 DER SEQUENCE 格式密文转换为 RAW C1C3C2 格式
 *
 * GmSSL sm2_encrypt 输出格式:
 *   SM2Cipher ::= SEQUENCE {
 *       XCoordinate  INTEGER,
 *       YCoordinate  INTEGER,
 *       HASH         OCTET STRING SIZE(32),
 *       CipherText   OCTET STRING }
 *
 * 目标输出格式:
 *   04 || x[32] || y[32] || c3[32] || c2[N]
 *
 * FIX-020: 新增函数，解决与 Python/Go/JS/Java/C# 的跨语言兼容性
 * ==================================================== */
static int sm2_der_to_raw_c1c3c2(const unsigned char* der, size_t der_len,
                                  unsigned char** raw_out, size_t* raw_len)
{
    /* 最小长度: SEQUENCE hdr(4) + INTEGER(2) + INTEGER(2+32) + OCT(2+32) + OCT(2+1) */
    if (!der || der_len < 80) return -1;
    if (der[0] != 0x30) return -1; /* 必须是 SEQUENCE */

    const unsigned char* p = der;
    const unsigned char* end = der + der_len;

    /* 跳过 SEQUENCE 头部 */
    if (*p != 0x30) return -1;
    p++;
    if (*p == 0x81) { p += 2; }
    else if (*p == 0x82) { p += 3; }
    else if (*p < 128) { p++; }
    else return -1;

    /* 跳过 INTEGER XCoordinate */
    if (*p != 0x02) return -1;
    p++;
    int xi_len = *p++;
    p += xi_len;

    /* 跳过 INTEGER YCoordinate */
    if (p >= end || *p != 0x02) return -1;
    p++;
    int yi_len = *p++;
    p += yi_len;

    /* 读取 OCTET STRING c3 (HASH, 32 bytes) */
    if (p >= end || *p != 0x04) return -1;
    p++;
    int c3_len = *p++;
    if (c3_len != 32 || p + c3_len > end) return -1;
    const unsigned char* c3 = p;
    p += c3_len;

    /* 读取 OCTET STRING c2 (CipherText) */
    if (p >= end || *p != 0x04) return -1;
    p++;
    int c2_len;
    if (*p == 0x81) { p++; c2_len = *p++; }
    else if (*p == 0x82) { c2_len = (*p++ << 8) | *p++; }
    else if (*p < 128) { c2_len = *p++; }
    else return -1;
    if (p + c2_len > end) return -1;
    const unsigned char* c2 = p;

    /* 现在需要从 DER 的 INTEGER 字段中恢复完整的 32 字节 X 和 Y */
    /* 重新解析以获得完整值 */
    const unsigned char* pp = der;
    /* 跳过 SEQUENCE hdr */
    pp++;
    if (*pp == 0x81) pp += 2; else if (*pp == 0x82) pp += 3; else pp++;
    /* INTEGER x */
    if (*pp++ != 0x02) return -1;
    int xl = *pp++;
    unsigned char x_buf[32] = {0};
    if (xl > 32) {
        pp += (xl - 32);
        xl = 32;
    }
    memcpy(x_buf + (32 - xl), pp, xl);
    pp += xl;
    /* INTEGER y */
    if (*pp++ != 0x02) return -1;
    int yl = *pp++;
    unsigned char y_buf[32] = {0};
    if (yl > 32) {
        pp += (yl - 32);
        yl = 32;
    }
    memcpy(y_buf + (32 - yl), pp, yl);

    /* 组装: 04 + x[32] + y[32] + c3[32] + c2 */
    size_t total = 1 + 32 + 32 + 32 + (size_t)c2_len;
    unsigned char* out = (unsigned char*)malloc(total);
    if (!out) return -1;

    unsigned char* op = out;
    *op++ = 0x04;
    memcpy(op, x_buf, 32); op += 32;
    memcpy(op, y_buf, 32); op += 32;
    memcpy(op, c3, 32); op += 32;
    memcpy(op, c2, c2_len);

    *raw_out = out;
    *raw_len = total;
    return 0;
}

/* ====================================================
 * 内部核心解密
 * 支持两种密文格式：
 *   1. GmSSL DER SEQUENCE 格式（30开头）
 *   2. Java/BouncyCastle RAW C1C3C2 格式（04开头：04||x[32]||y[32]||C3[32]||C2[N]）
 * ==================================================== */
static int sm2_decrypt_core(const char* ciphertext_str, const char* private_key,
                             unsigned char** plaintext, size_t* plaintext_len)
{
    unsigned char priv_bytes[SM2_PRIVATE_KEY_SIZE];
    size_t priv_len = 0;
    unsigned char* ct_bytes = NULL;
    size_t ct_len = 0;
    unsigned char* der_bytes = NULL; /* DER 格式密文（可能是转换后的） */
    size_t der_len = 0;
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

    /* 判断密文格式：
     *   - 0x30 开头 => GmSSL DER SEQUENCE 格式，直接使用
     *   - 0x04 开头 => Java RAW C1C3C2 格式（04||x||y||C3||C2），需转换为 DER
     */
    if (ct_len > 0 && ct_bytes[0] == 0x04) {
        /* Java RAW 格式 → 转换为 GmSSL DER SEQUENCE */
        if (sm2_raw_c1c3c2_to_der(ct_bytes, ct_len, &der_bytes, &der_len) != 0) {
            free(ct_bytes);
            return CROSSMOOL_ERR_FORMAT_CONVERSION;
        }
        free(ct_bytes);
        ct_bytes = NULL;
    } else {
        /* 已是 DER SEQUENCE 格式或其他格式，直接使用 */
        der_bytes = ct_bytes;
        der_len   = ct_len;
        ct_bytes  = NULL; /* 转移所有权，避免重复释放 */
    }

    buf = (unsigned char*)malloc(der_len);
    if (!buf) { free(der_bytes); return CROSSMOOL_ERR_MEMORY_ALLOC; }

    ret = sm2_decrypt(&key, der_bytes, der_len, buf, &actual_len);
    free(der_bytes);
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
 * 内部辅助：将 Java DER 编码签名转换为 GmSSL 期望的 r||s 格式
 * Java BouncyCastle 输出：SEQUENCE { INTEGER r, INTEGER s }
 * GmSSL 期望格式：r[32 字节] || s[32 字节]（共 64 字节）
 * ==================================================== */
static int sm2_signature_der_to_raw(const unsigned char* der_sig, size_t der_len,
                                     unsigned char* raw_sig, size_t* raw_len)
{
    const unsigned char* p = der_sig;
    const unsigned char* end = der_sig + der_len;

    /* 解析 SEQUENCE 头 */
    if (p >= end || *p != 0x30) return -1;  /* 不是 DER SEQUENCE */
    p++;

    /* 解析 SEQUENCE 长度 */
    if (p >= end) return -1;
    size_t seq_len = *p;
    if (seq_len & 0x80) {  /* 长格式长度 */
        size_t len_bytes = seq_len & 0x7f;
        if (len_bytes == 0 || p + len_bytes > end) return -1;
        seq_len = 0;
        for (size_t i = 0; i < len_bytes; i++) {
            seq_len = (seq_len << 8) | p[1 + i];
        }
        p += 1 + len_bytes;
    } else {
        p++;
    }

    if (p + seq_len > end) return -1;
    end = p + seq_len;  /* 更新结束位置 */

    /* 解析 INTEGER r */
    if (p >= end || *p != 0x02) return -1;  /* 不是 INTEGER */
    p++;
    if (p >= end) return -1;
    size_t r_len = *p;
    if (r_len & 0x80) {  /* 长格式长度 */
        size_t len_bytes = r_len & 0x7f;
        if (len_bytes == 0 || p + len_bytes > end) return -1;
        r_len = 0;
        for (size_t i = 0; i < len_bytes; i++) {
            r_len = (r_len << 8) | p[1 + i];
        }
        p += 1 + len_bytes;
    } else {
        p++;
    }
    if (p + r_len > end) return -1;

    /* 保存 r 的起始位置 */
    const unsigned char* r_start = p;
    /* 跳过 r 值 */
    p += r_len;
    
    /* 解析 INTEGER s */
    if (p >= end || *p != 0x02) return -1;  /* 不是 INTEGER */
    p++;
    if (p >= end) return -1;
    size_t s_len = *p;
    if (s_len & 0x80) {  /* 长格式长度 */
        size_t len_bytes = s_len & 0x7f;
        if (len_bytes == 0 || p + len_bytes > end) return -1;
        s_len = 0;
        for (size_t i = 0; i < len_bytes; i++) {
            s_len = (s_len << 8) | p[1 + i];
        }
        p += 1 + len_bytes;
    } else {
        p++;
    }
    if (p + s_len > end) return -1;

    /* 将 r 和 s 填充为各 32 字节并拼接 */
    memset(raw_sig, 0, 32);
    memset(raw_sig + 32, 0, 32);
    
    /* 处理 r：跳过前导零（ASN.1 INTEGER 为表示正数可能添加 0x00） */
    size_t r_offset = 0;
    while (r_offset < r_len && r_start[r_offset] == 0x00) {
        r_offset++;
    }
    size_t r_actual_len = r_len - r_offset;
    if (r_actual_len > 32) r_actual_len = 32;
    memcpy(raw_sig + 32 - r_actual_len, r_start + r_offset, r_actual_len);
    
    /* 处理 s：跳过前导零 */
    size_t s_offset = 0;
    while (s_offset < s_len && p[s_offset] == 0x00) {
        s_offset++;
    }
    size_t s_actual_len = s_len - s_offset;
    if (s_actual_len > 32) s_actual_len = 32;
    memcpy(raw_sig + 64 - s_actual_len, p + s_offset, s_actual_len);

    *raw_len = 64;
    return 0;
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
    unsigned char raw_sig[64];  /* 用于存储转换后的 r||s 格式 */
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

    /* GmSSL 的 sm2_verify_finish 期望 DER 格式签名，直接使用 */
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

    /* 对密文字符串签名，与 Java SM2Util.encryptSign 一致 */
    ret = crossmool_sm2_sign(pair->ciphertext_hex, "UTF-8", sign_private_key, &pair->signature_hex);
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

    /* 先验签：对密文字符串 (UTF-8) 进行验签，与 Java SM2Util.verifyDecrypt 一致 */
    int ret = sm2_verify_core((const unsigned char*)ciphertext, strlen(ciphertext), signature, sign_public_key);
    if (ret != 1) {
        return (ret < 0) ? ret : CROSSMOOL_ERR_SIGN_VERIFY;
    }

    /* 验签成功后再解密 */
    unsigned char* pt = NULL; size_t pt_len = 0;
    ret = sm2_decrypt_core(ciphertext, dec_private_key, &pt, &pt_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

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

/* ============================================================
 * PEM Export / Import
 * ============================================================ */

static int der_to_pem(const char* type, const unsigned char* der, size_t der_len, char** pem_out)
{
    char* b64 = NULL;
    int ret = crossmool_base64_encode(der, der_len, &b64);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    size_t b64_len = strlen(b64);
    size_t pem_len = strlen("-----BEGIN -----\n") + strlen(type) * 2 + b64_len + (b64_len / 64 + 1) + 4;
    char* pem = (char*)malloc(pem_len);
    if (!pem) { free(b64); return CROSSMOOL_ERR_MEMORY_ALLOC; }

    char* p = pem;
    p += sprintf(p, "-----BEGIN %s-----\n", type);
    for (size_t i = 0; i < b64_len; i += 64) {
        size_t chunk = b64_len - i;
        if (chunk > 64) chunk = 64;
        memcpy(p, b64 + i, chunk);
        p += chunk;
        *p++ = '\n';
    }
    p += sprintf(p, "-----END %s-----\n", type);

    free(b64);
    *pem_out = pem;
    return CROSSMOOL_SUCCESS;
}

static int pem_to_der(const char* type, const char* pem, unsigned char** der_out, size_t* der_len)
{
    char begin[128], end[128];
    snprintf(begin, sizeof(begin), "-----BEGIN %s-----", type);
    snprintf(end, sizeof(end), "-----END %s-----", type);

    const char* start = strstr(pem, begin);
    const char* finish = strstr(pem, end);
    if (!start || !finish || finish <= start) {
        return CROSSMOOL_ERR_FORMAT_CONVERSION;
    }
    start += strlen(begin);

    // Extract base64 content (remove whitespace)
    size_t b64_len = finish - start;
    char* b64 = (char*)malloc(b64_len + 1);
    if (!b64) return CROSSMOOL_ERR_MEMORY_ALLOC;
    size_t j = 0;
    for (size_t i = 0; i < b64_len; i++) {
        if (start[i] != ' ' && start[i] != '\n' && start[i] != '\r' && start[i] != '\t') {
            b64[j++] = start[i];
        }
    }
    b64[j] = '\0';

    int ret = crossmool_base64_decode(b64, der_out, der_len);
    free(b64);
    return ret;
}

int crossmool_sm2_export_public_key_pem(const char* public_key_hex, char** pem_out)
{
    if (!public_key_hex || !pem_out) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* pub_bytes = NULL;
    size_t pub_len = 0;
    int ret = crossmool_hex_decode(public_key_hex, &pub_bytes, &pub_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    // Build SM2_KEY with only the public key set
    SM2_KEY sm2_key;
    memset(&sm2_key, 0, sizeof(sm2_key));
    SM2_POINT point;
    if (!decode_public_key_to_point(pub_bytes, pub_len, &point)) {
        free(pub_bytes);
        return CROSSMOOL_ERR_KEY_INVALID;
    }
    free(pub_bytes);

    if (sm2_key_set_public_key(&sm2_key, &point) != 1) {
        return CROSSMOOL_ERR_KEY_INVALID;
    }

    uint8_t* der = NULL;
    size_t der_len = 0;
    if (sm2_public_key_info_to_der(&sm2_key, &der, &der_len) != 1) {
        return CROSSMOOL_ERR_FORMAT_CONVERSION;
    }

    ret = der_to_pem("PUBLIC KEY", der, der_len, pem_out);
    free(der);
    return ret;
}

int crossmool_sm2_export_private_key_pem(const char* private_key_hex, const char* public_key_hex, char** pem_out)
{
    if (!private_key_hex || !pem_out) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* priv_bytes = NULL;
    size_t priv_len = 0;
    int ret = crossmool_hex_decode(private_key_hex, &priv_bytes, &priv_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;
    if (priv_len != 32) { free(priv_bytes); return CROSSMOOL_ERR_KEY_INVALID; }

    SM2_KEY sm2_key;
    memset(&sm2_key, 0, sizeof(sm2_key));
    memcpy(sm2_key.private_key, priv_bytes, 32);
    free(priv_bytes);

    // Set the public key by deriving it from the private key
    if (sm2_key_set_private_key(&sm2_key, sm2_key.private_key) != 1) {
        return CROSSMOOL_ERR_KEY_INVALID;
    }

    uint8_t* der = NULL;
    size_t der_len = 0;
    if (sm2_private_key_info_to_der(&sm2_key, &der, &der_len) != 1) {
        return CROSSMOOL_ERR_FORMAT_CONVERSION;
    }

    ret = der_to_pem("PRIVATE KEY", der, der_len, pem_out);
    free(der);
    return ret;
}

int crossmool_sm2_import_public_key_pem(const char* pem, char** hex_out)
{
    if (!pem || !hex_out) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* der = NULL;
    size_t der_len = 0;
    int ret = pem_to_der("PUBLIC KEY", pem, &der, &der_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    SM2_KEY sm2_key;
    memset(&sm2_key, 0, sizeof(sm2_key));
    const uint8_t* der_ptr = der;
    size_t remaining = der_len;
    if (sm2_public_key_info_from_der(&sm2_key, &der_ptr, &remaining) != 1) {
        free(der);
        return CROSSMOOL_ERR_KEY_INVALID;
    }
    free(der);

    unsigned char pub_bytes[65];
    sm2_point_to_uncompressed_octets(&sm2_key.public_key, pub_bytes);
    ret = crossmool_hex_encode(pub_bytes, 65, hex_out);
    return ret;
}

int crossmool_sm2_import_private_key_pem(const char* pem, char** hex_out)
{
    if (!pem || !hex_out) return CROSSMOOL_ERR_INVALID_PARAM;

    unsigned char* der = NULL;
    size_t der_len = 0;
    int ret = pem_to_der("PRIVATE KEY", pem, &der, &der_len);
    if (ret != CROSSMOOL_SUCCESS) return ret;

    SM2_KEY sm2_key;
    memset(&sm2_key, 0, sizeof(sm2_key));
    const uint8_t* der_ptr = der;
    size_t remaining = der_len;
    const uint8_t* attrs = NULL;
    size_t attrs_len = 0;
    if (sm2_private_key_info_from_der(&sm2_key, &attrs, &attrs_len, &der_ptr, &remaining) != 1) {
        free(der);
        return CROSSMOOL_ERR_KEY_INVALID;
    }
    free(der);

    ret = crossmool_hex_encode(sm2_key.private_key, 32, hex_out);
    return ret;
}
