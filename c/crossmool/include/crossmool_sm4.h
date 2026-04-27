#ifndef CROSSMOOL_SM4_H
#define CROSSMOOL_SM4_H

#include "crossmool_error.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CROSSMOOL_SM4_KEY_SIZE 16  // SM4 密钥长度（16 字节）

/**
 * 生成 SM4 密钥
 * @param key 输出参数，存储生成的密钥（至少 16 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm4_generate_key(unsigned char* key);

/**
 * 生成 SM4 密钥（返回 HEX 字符串）
 * @param key_hex 输出参数，存储 HEX 编码的密钥
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 key_hex 内存
 */
int crossmool_sm4_generate_key_hex(char** key_hex);

/**
 * 解析 HEX 密钥字符串
 * @param hex_key HEX 编码的密钥字符串
 * @param key 输出参数，存储解析后的密钥（至少 16 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm4_parse_hex_key(const char* hex_key, unsigned char* key);

/**
 * SM4 ECB 模式加密（返回 HEX 字符串）
 * @param key 密钥（16 字节）
 * @param plaintext 明文数据
 * @param plaintext_len 明文长度
 * @param ciphertext_hex 输出参数，存储 HEX 编码的密文
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 ciphertext_hex 内存
 */
int crossmool_sm4_encrypt_ecb(
    const unsigned char* key,
    const unsigned char* plaintext,
    size_t plaintext_len,
    char** ciphertext_hex
);

/**
 * SM4 ECB 模式解密
 * @param key 密钥（16 字节）
 * @param ciphertext_hex HEX 编码的密文
 * @param plaintext 输出参数，存储解密后的明文
 * @param plaintext_len 输出参数，存储明文长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 plaintext 内存
 */
int crossmool_sm4_decrypt_ecb(
    const unsigned char* key,
    const char* ciphertext_hex,
    unsigned char** plaintext,
    size_t* plaintext_len
);

#ifdef __cplusplus
}
#endif

#endif // CROSSMOOL_SM4_H