#ifndef CROSSMOOL_SM4_H
#define CROSSMOOL_SM4_H

#include "crossmool_error.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CROSSMOOL_SM4_KEY_SIZE 16       // SM4 密钥长度（16 字节）
#define CROSSMOOL_SM4_GCM_IV_SIZE 12    // GCM IV 长度（12 字节 = 96 bits）
#define CROSSMOOL_SM4_GCM_TAG_SIZE 16   // GCM 认证标签长度（16 字节 = 128 bits）

/**
 * 生成 SM4 密钥
 * @param key 输出参数，存储生成的密钥（至少 16 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
CROSSMOOL_API int crossmool_sm4_generate_key(unsigned char* key);

/**
 * 生成 SM4 密钥（返回 HEX 字符串）
 * @param key_hex 输出参数，存储 HEX 编码的密钥
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 key_hex 内存
 */
CROSSMOOL_API int crossmool_sm4_generate_key_hex(char** key_hex);

/**
 * 解析 HEX 密钥字符串
 * @param hex_key HEX 编码的密钥字符串
 * @param key 输出参数，存储解析后的密钥（至少 16 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
CROSSMOOL_API int crossmool_sm4_parse_hex_key(const char* hex_key, unsigned char* key);

/**
 * 生成随机 IV（12 字节）
 * @param iv 输出参数，存储生成的 IV（至少 12 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
CROSSMOOL_API int crossmool_sm4_generate_iv(unsigned char* iv);

/**
 * SM4 GCM 模式加密（返回 HEX 字符串）【优先使用】
 * 输出格式：Hex(IV[12字节] + 密文 + Tag[16字节])
 * @param key 密钥（16 字节）
 * @param plaintext 明文数据
 * @param plaintext_len 明文长度
 * @param ciphertext_hex 输出参数，存储 HEX 编码的 IV+密文+Tag
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 ciphertext_hex 内存
 */
CROSSMOOL_API int crossmool_sm4_encrypt_gcm_hex(
    const unsigned char* key,
    const unsigned char* plaintext,
    size_t plaintext_len,
    char** ciphertext_hex
);

/**
 * SM4 GCM 模式加密（返回 Base64 字符串）
 * 输出格式：Base64(IV[12字节] + 密文 + Tag[16字节])
 * @param key 密钥（16 字节）
 * @param plaintext 明文数据
 * @param plaintext_len 明文长度
 * @param ciphertext_base64 输出参数，存储 Base64 编码的 IV+密文+Tag
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 ciphertext_base64 内存
 */
CROSSMOOL_API int crossmool_sm4_encrypt_gcm_base64(
    const unsigned char* key,
    const unsigned char* plaintext,
    size_t plaintext_len,
    char** ciphertext_base64
);

/**
 * SM4 GCM 模式解密（从 HEX 字符串）【优先使用】
 * 输入格式：Hex(IV[12字节] + 密文 + Tag[16字节])
 * @param key 密钥（16 字节）
 * @param ciphertext_hex HEX 编码的（IV + 密文 + Tag）
 * @param plaintext 输出参数，存储解密后的明文
 * @param plaintext_len 输出参数，存储明文长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 plaintext 内存
 */
CROSSMOOL_API int crossmool_sm4_decrypt_gcm_hex(
    const unsigned char* key,
    const char* ciphertext_hex,
    unsigned char** plaintext,
    size_t* plaintext_len
);

/**
 * SM4 GCM 模式解密（从 Base64 字符串）
 * 输入格式：Base64(IV[12字节] + 密文 + Tag[16字节])
 * @param key 密钥（16 字节）
 * @param ciphertext_base64 Base64 编码的（IV + 密文 + Tag）
 * @param plaintext 输出参数，存储解密后的明文
 * @param plaintext_len 输出参数，存储明文长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 plaintext 内存
 */
CROSSMOOL_API int crossmool_sm4_decrypt_gcm_base64(
    const unsigned char* key,
    const char* ciphertext_base64,
    unsigned char** plaintext,
    size_t* plaintext_len
);

/**
 * @deprecated 请使用 crossmool_sm4_encrypt_gcm_hex 或 crossmool_sm4_encrypt_gcm_base64
 * SM4 GCM 模式加密（返回 Base64 字符串，保持向后兼容）
 */
CROSSMOOL_API int crossmool_sm4_encrypt_gcm(
    const unsigned char* key,
    const unsigned char* plaintext,
    size_t plaintext_len,
    char** ciphertext_base64
);

/**
 * @deprecated 请使用 crossmool_sm4_decrypt_gcm_hex 或 crossmool_sm4_decrypt_gcm_base64
 * SM4 GCM 模式解密（保持向后兼容）
 */
CROSSMOOL_API int crossmool_sm4_decrypt_gcm(
    const unsigned char* key,
    const char* ciphertext_base64,
    unsigned char** plaintext,
    size_t* plaintext_len
);

#ifdef __cplusplus
}
#endif

#endif // CROSSMOOL_SM4_H
