#ifndef CROSSMOOL_SM2_H
#define CROSSMOOL_SM2_H

#include "crossmool_error.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// SM2 密钥对结构（同时存储 HEX 和 Base64 格式）
typedef struct {
    char* private_key;          // 原始私钥（Base64 或 HEX，由生成方式决定）
    char* public_key;           // 原始公钥（Base64 或 HEX，由生成方式决定）
    char* private_key_hex;      // HEX 格式私钥（调用 crossmool_sm2_keypair_to_hex 后赋值）
    char* public_key_hex;       // HEX 格式公钥
    char* private_key_base64;   // Base64 格式私钥（调用 crossmool_sm2_keypair_to_base64 后赋值）
    char* public_key_base64;    // Base64 格式公钥
} crossmool_sm2_keypair_t;

// 密文签名对结构
typedef struct {
    char* ciphertext;       // 密文（与加密格式一致）
    char* signature;        // 签名（与签名格式一致）
    char* ciphertext_hex;   // HEX 格式密文（encrypt_sign 使用 HEX 时赋值）
    char* signature_hex;    // HEX 格式签名
    char* ciphertext_base64;// Base64 格式密文（encrypt_sign 使用 Base64 时赋值）
    char* signature_base64; // Base64 格式签名
} crossmool_sm2_cipher_sig_pair_t;

/* ====================================================
 * 密钥生成
 * ==================================================== */

/**
 * 生成 SM2 密钥对（返回指针，自动分配内存）
 * 密钥默认以 HEX 格式存储在 private_key/public_key 字段中
 * @param keypair 输出参数，存储生成的密钥对指针
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 crossmool_sm2_keypair_free() 释放内存
 */
int crossmool_sm2_generate_keypair(crossmool_sm2_keypair_t** keypair);

/**
 * 将密钥对转换为 HEX 格式（填充 private_key_hex / public_key_hex 字段）
 * @param keypair 已生成的密钥对
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm2_keypair_to_hex(crossmool_sm2_keypair_t* keypair);

/**
 * 将密钥对转换为 Base64 格式（填充 private_key_base64 / public_key_base64 字段）
 * @param keypair 已生成的密钥对
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm2_keypair_to_base64(crossmool_sm2_keypair_t* keypair);

/**
 * 生成 SM2 密钥对（Base64 编码，直接结构体）
 * @param keypair 输出参数，存储生成的密钥对
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm2_generate_keypair_base64(crossmool_sm2_keypair_t* keypair);

/**
 * 生成 SM2 密钥对（HEX 编码，直接结构体）
 * @param keypair 输出参数，存储生成的密钥对
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm2_generate_keypair_hex(crossmool_sm2_keypair_t* keypair);

/**
 * 释放密钥对内存（指针版本）
 * @param keypair 要释放的密钥对指针
 */
void crossmool_sm2_keypair_free(crossmool_sm2_keypair_t* keypair);

/* ====================================================
 * 加密 / 解密
 * ==================================================== */

/**
 * SM2 加密（自动检测 charset，输出 HEX 字符串）
 * @param content  明文字符串（C字符串，以'\0'结束）
 * @param charset  字符集（可为 NULL，表示 UTF-8）
 * @param public_key 公钥（支持 HEX 或 Base64）
 * @param ciphertext_hex 输出 HEX 格式密文
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 ciphertext_hex
 */
int crossmool_sm2_encrypt(
    const char* content,
    const char* charset,
    const char* public_key,
    char** ciphertext_hex
);

/**
 * SM2 解密（自动检测格式，输出字符串）
 * @param ciphertext 密文（HEX 或 Base64 字符串）
 * @param private_key 私钥（支持 HEX 或 Base64）
 * @param charset 字符集（可为 NULL）
 * @param plaintext_str 输出明文字符串
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 plaintext_str
 */
int crossmool_sm2_decrypt(
    const char* ciphertext,
    const char* private_key,
    const char* charset,
    char** plaintext_str
);

/**
 * SM2 加密（返回字节数组）
 * @param content 明文数据
 * @param content_len 明文长度
 * @param public_key 公钥
 * @param ciphertext 输出密文
 * @param ciphertext_len 输出密文长度
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm2_encrypt_bytes(
    const unsigned char* content,
    size_t content_len,
    const char* public_key,
    unsigned char** ciphertext,
    size_t* ciphertext_len
);

/**
 * SM2 加密（返回 HEX 字符串，字节数组输入）
 */
int crossmool_sm2_encrypt_to_hex(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* public_key,
    char** ciphertext_hex
);

/**
 * SM2 加密（返回 Base64 字符串，字节数组输入）
 */
int crossmool_sm2_encrypt_to_base64(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* public_key,
    char** ciphertext_base64
);

/**
 * SM2 解密（返回字节数组）
 */
int crossmool_sm2_decrypt_bytes(
    const char* ciphertext,
    const char* private_key,
    unsigned char** plaintext,
    size_t* plaintext_len
);

/**
 * SM2 解密并转换为字符串
 */
int crossmool_sm2_decrypt_to_string(
    const char* ciphertext,
    const char* private_key,
    const char* charset,
    char** plaintext_str
);

/* ====================================================
 * 签名 / 验签
 * ==================================================== */

/**
 * SM2 签名（自动检测 charset，输出 HEX 字符串）
 * @param content 待签名字符串（C字符串，以'\0'结束）
 * @param charset 字符集（可为 NULL）
 * @param private_key 私钥（支持 HEX 或 Base64）
 * @param signature_hex 输出 HEX 格式签名
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 signature_hex
 */
int crossmool_sm2_sign(
    const char* content,
    const char* charset,
    const char* private_key,
    char** signature_hex
);

/**
 * SM2 验签
 * @param content 原始字符串（C字符串）
 * @param charset 字符集（可为 NULL）
 * @param signature 签名（HEX 或 Base64）
 * @param public_key 公钥（HEX 或 Base64）
 * @return 验证成功返回 1，失败返回 0，错误返回负数
 */
int crossmool_sm2_verify(
    const char* content,
    const char* charset,
    const char* signature,
    const char* public_key
);

/**
 * SM2 签名（字节数组输入，返回字节数组）
 */
int crossmool_sm2_sign_bytes(
    const unsigned char* content,
    size_t content_len,
    const char* private_key,
    unsigned char** signature,
    size_t* signature_len
);

/**
 * SM2 签名（字节数组输入，返回 HEX 字符串）
 */
int crossmool_sm2_sign_to_hex(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* private_key,
    char** signature_hex
);

/**
 * SM2 签名（字节数组输入，返回 Base64 字符串）
 */
int crossmool_sm2_sign_to_base64(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* private_key,
    char** signature_base64
);

/**
 * SM2 验签（字节数组输入）
 */
int crossmool_sm2_verify_bytes(
    const unsigned char* content,
    size_t content_len,
    const char* signature,
    const char* public_key
);

/* ====================================================
 * 加密+签名组合 / 验签+解密组合
 * ==================================================== */

/**
 * 加密并签名（字符串输入，输出 HEX）
 * @param content 明文字符串
 * @param charset 字符集（可为 NULL）
 * @param enc_public_key 加密用公钥
 * @param sign_private_key 签名用私钥
 * @param result 输出密文签名对指针（自动分配）
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 crossmool_sm2_cipher_sig_pair_free() 释放内存
 */
int crossmool_sm2_encrypt_sign(
    const char* content,
    const char* charset,
    const char* enc_public_key,
    const char* sign_private_key,
    crossmool_sm2_cipher_sig_pair_t** result
);

/**
 * 验签并解密（字符串输出）
 * @param ciphertext 密文（HEX 或 Base64）
 * @param signature 签名（HEX 或 Base64）
 * @param sign_public_key 验签用公钥
 * @param dec_private_key 解密用私钥
 * @param charset 字符集（可为 NULL）
 * @param plaintext 输出明文字符串
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm2_verify_decrypt(
    const char* ciphertext,
    const char* signature,
    const char* sign_public_key,
    const char* dec_private_key,
    const char* charset,
    char** plaintext
);

/**
 * 加密并签名（字节数组输入，支持 HEX 或 Base64 输出）
 * @param to_base64 0=HEX, 1=Base64
 */
int crossmool_sm2_encrypt_sign_ex(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* enc_public_key,
    const char* sign_private_key,
    int to_base64,
    crossmool_sm2_cipher_sig_pair_t* result
);

/**
 * 释放密文签名对内存（指针版本）
 */
void crossmool_sm2_cipher_sig_pair_free(crossmool_sm2_cipher_sig_pair_t* pair);

#ifdef __cplusplus
}
#endif

#endif // CROSSMOOL_SM2_H
