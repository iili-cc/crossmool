#ifndef CROSSMOOL_UTIL_H
#define CROSSMOOL_UTIL_H

#include "crossmool_error.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 判断字符串是否为 HEX 格式
 * @param str 输入字符串
 * @return 是 HEX 格式返回 1，否则返回 0
 */
int crossmool_is_hex_string(const char* str);

/**
 * 判断字符串是否为 Base64 格式
 * @param str 输入字符串
 * @return 是 Base64 格式返回 1，否则返回 0
 */
int crossmool_is_base64_string(const char* str);

/**
 * HEX 编码
 * @param data 输入数据
 * @param data_len 数据长度
 * @param hex_str 输出参数，存储 HEX 编码字符串
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 hex_str 内存
 */
int crossmool_hex_encode(const unsigned char* data, size_t data_len, char** hex_str);

/**
 * HEX 解码
 * @param hex_str HEX 编码字符串
 * @param data 输出参数，存储解码后的数据
 * @param data_len 输出参数，存储数据长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 data 内存
 */
int crossmool_hex_decode(const char* hex_str, unsigned char** data, size_t* data_len);

/**
 * Base64 编码
 * @param data 输入数据
 * @param data_len 数据长度
 * @param base64_str 输出参数，存储 Base64 编码字符串
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 base64_str 内存
 */
int crossmool_base64_encode(const unsigned char* data, size_t data_len, char** base64_str);

/**
 * Base64 解码
 * @param base64_str Base64 编码字符串
 * @param data 输出参数，存储解码后的数据
 * @param data_len 输出参数，存储数据长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 data 内存
 */
int crossmool_base64_decode(const char* base64_str, unsigned char** data, size_t* data_len);

/**
 * 字符串转字节数组（支持字符集）
 * @param str 输入字符串
 * @param charset 字符集（如"UTF-8"、"GBK"）
 * @param data 输出参数，存储字节数组
 * @param data_len 输出参数，存储字节长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 data 内存
 */
int crossmool_string_to_bytes(
    const char* str,
    const char* charset,
    unsigned char** data,
    size_t* data_len
);

/**
 * 字节数组转字符串（支持字符集）
 * @param data 字节数组
 * @param data_len 字节长度
 * @param charset 字符集
 * @param str 输出参数，存储字符串
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 str 内存
 */
int crossmool_bytes_to_string(
    const unsigned char* data,
    size_t data_len,
    const char* charset,
    char** str
);

/**
 * 清理全局资源（可选调用）
 */
void crossmool_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // CROSSMOOL_UTIL_H