#ifndef CROSSMOOL_SM3_H
#define CROSSMOOL_SM3_H

#include "crossmool_error.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CROSSMOOL_SM3_DIGEST_SIZE 32  // SM3 杂凑值长度（32 字节）

/* ====================================================
 * 杂凑计算
 * ==================================================== */

/**
 * SM3 杂凑（返回字节数组）
 * @param data 输入数据
 * @param data_len 数据长度
 * @param digest 输出参数，存储杂凑值（至少 32 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm3_digest(
    const unsigned char* data,
    size_t data_len,
    unsigned char* digest
);

/**
 * SM3 杂凑（字节数组输入，返回 HEX 字符串）
 * @param data 输入数据
 * @param data_len 数据长度
 * @param digest_hex 输出参数
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 digest_hex 内存
 */
int crossmool_sm3_digest_to_hex(
    const unsigned char* data,
    size_t data_len,
    char** digest_hex
);

/**
 * SM3 杂凑（字节数组输入，返回 Base64 字符串）
 */
int crossmool_sm3_digest_to_base64(
    const unsigned char* data,
    size_t data_len,
    char** digest_base64
);

/**
 * SM3 杂凑（字符串输入，返回 HEX 字符串）
 * @param str 输入字符串
 * @param charset 字符集（NULL 表示 UTF-8）
 * @param digest_hex 输出 HEX 杂凑值
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 digest_hex 内存
 */
int crossmool_sm3_digest_str(
    const char* str,
    const char* charset,
    char** digest_hex
);

/**
 * SM3 杂凑（字符串输入，返回 Base64 字符串）
 */
int crossmool_sm3_digest_str_to_base64(
    const char* str,
    const char* charset,
    char** digest_base64
);

/* ====================================================
 * HMAC-SM3
 * ==================================================== */

/**
 * 生成 HMAC-SM3 密钥
 * @param key_length 密钥长度（字节，至少 32）
 * @param key 输出参数，存储生成的密钥
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 key 内存
 */
int crossmool_sm3_generate_hmac_key(
    size_t key_length,
    unsigned char** key
);

/**
 * HMAC-SM3（字节数组输入，返回字节数组）
 * @param key HMAC 密钥
 * @param key_len 密钥长度
 * @param data 输入数据
 * @param data_len 数据长度
 * @param mac 输出参数，存储 HMAC 值（至少 32 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm3_hmac(
    const unsigned char* key,
    size_t key_len,
    const unsigned char* data,
    size_t data_len,
    unsigned char* mac
);

/**
 * HMAC-SM3（HEX 编码密钥，字节数组数据，返回 HEX 字符串）
 */
int crossmool_sm3_hmac_hex(
    const char* key_hex,
    const unsigned char* data,
    size_t data_len,
    char** hmac_hex
);

/**
 * HMAC-SM3（字符串密钥和数据，返回 HEX 字符串）
 * @param key_str 密钥字符串
 * @param charset 密钥字符集（NULL 表示 UTF-8）
 * @param data_str 数据字符串
 * @param data_charset 数据字符集（NULL 表示 UTF-8）
 * @param hmac_hex 输出 HEX 格式 HMAC 值
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 hmac_hex 内存
 */
int crossmool_sm3_hmac_str(
    const char* key_str,
    const char* charset,
    const char* data_str,
    const char* data_charset,
    char** hmac_hex
);

/**
 * HMAC-SM3（字符串接口，返回 HEX）
 * @param key HMAC 密钥（支持 HEX 或 Base64 字符串）
 * @param data 输入数据（支持 HEX、Base64 或 UTF-8 字符串）
 * @param mac_hex 输出参数，存储 HEX 编码的 HMAC 值
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm3_hmac_to_hex(
    const char* key,
    const char* data,
    char** mac_hex
);

/**
 * HMAC-SM3（字符串接口，返回 Base64）
 */
int crossmool_sm3_hmac_to_base64(
    const char* key,
    const char* data,
    char** mac_base64
);

/**
 * 验证 HMAC-SM3（字符串接口）
 * @param key 密钥字符串
 * @param charset 密钥字符集（NULL 表示 UTF-8）
 * @param data 数据字符串
 * @param data_charset 数据字符集（NULL 表示 UTF-8）
 * @param received_mac 接收到的 HMAC（HEX 或 Base64）
 * @return 验证成功返回 1，失败返回 0，错误返回负数
 */
int crossmool_sm3_hmac_verify(
    const char* key,
    const char* charset,
    const char* data,
    const char* data_charset,
    const char* received_mac
);

#ifdef __cplusplus
}
#endif

#endif // CROSSMOOL_SM3_H
