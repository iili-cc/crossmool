#include "crossmool_sm4.h"
#include "crossmool_util.h"
#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <stdlib.h>
#include <string.h>

/**
 * 生成 SM4 密钥
 * @param key 输出参数，存储生成的密钥（至少 16 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm4_generate_key(unsigned char* key) {
    if (key == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    if (rand_bytes(key, CROSSMOOL_SM4_KEY_SIZE) != 1) {
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }

    return CROSSMOOL_SUCCESS;
}

/**
 * 生成 SM4 密钥（返回 HEX 字符串）
 * @param key_hex 输出参数，存储 HEX 编码的密钥
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 key_hex 内存
 */
int crossmool_sm4_generate_key_hex(char** key_hex) {
    unsigned char key[CROSSMOOL_SM4_KEY_SIZE];
    int ret;

    if (key_hex == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    ret = crossmool_sm4_generate_key(key);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }

    ret = crossmool_hex_encode(key, CROSSMOOL_SM4_KEY_SIZE, key_hex);

    return ret;
}

/**
 * 解析 HEX 密钥字符串
 * @param hex_key HEX 编码的密钥字符串
 * @param key 输出参数，存储解析后的密钥（至少 16 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm4_parse_hex_key(const char* hex_key, unsigned char* key) {
    unsigned char* decoded_key = NULL;
    size_t key_len = 0;
    int ret;

    if (hex_key == NULL || key == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    ret = crossmool_hex_decode(hex_key, &decoded_key, &key_len);
    if (ret != CROSSMOOL_SUCCESS || key_len != CROSSMOOL_SM4_KEY_SIZE) {
        if (decoded_key) {
            free(decoded_key);
        }
        return CROSSMOOL_ERR_KEY_INVALID;
    }

    memcpy(key, decoded_key, CROSSMOOL_SM4_KEY_SIZE);
    free(decoded_key);

    return CROSSMOOL_SUCCESS;
}

/**
 * 生成随机 IV（12 字节）
 * @param iv 输出参数，存储生成的 IV（至少 12 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm4_generate_iv(unsigned char* iv) {
    if (iv == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    if (rand_bytes(iv, CROSSMOOL_SM4_GCM_IV_SIZE) != 1) {
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }

    return CROSSMOOL_SUCCESS;
}

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
int crossmool_sm4_encrypt_gcm(
    const unsigned char* key,
    const unsigned char* plaintext,
    size_t plaintext_len,
    char** ciphertext_base64
) {
    unsigned char iv[CROSSMOOL_SM4_GCM_IV_SIZE];
    unsigned char* ciphertext = NULL;
    unsigned char tag[CROSSMOOL_SM4_GCM_TAG_SIZE];
    unsigned char* combined = NULL;
    size_t combined_len;
    SM4_KEY sm4_key;
    int ret;

    if (key == NULL || plaintext == NULL || ciphertext_base64 == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    /* 生成随机 IV */
    ret = crossmool_sm4_generate_iv(iv);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }

    /* 分配密文缓冲区（GCM 密文长度与明文相同，无填充） */
    ciphertext = (unsigned char*)malloc(plaintext_len);
    if (ciphertext == NULL) {
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }

    /* 设置加密密钥并执行 GCM 加密 */
    sm4_set_encrypt_key(&sm4_key, key);
    if (sm4_gcm_encrypt(&sm4_key, iv, CROSSMOOL_SM4_GCM_IV_SIZE,
            NULL, 0, plaintext, plaintext_len,
            ciphertext, CROSSMOOL_SM4_GCM_TAG_SIZE, tag) != 1) {
        free(ciphertext);
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }

    /* 组合 IV + 密文 + Tag */
    combined_len = CROSSMOOL_SM4_GCM_IV_SIZE + plaintext_len + CROSSMOOL_SM4_GCM_TAG_SIZE;
    combined = (unsigned char*)malloc(combined_len);
    if (combined == NULL) {
        free(ciphertext);
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }

    memcpy(combined, iv, CROSSMOOL_SM4_GCM_IV_SIZE);
    memcpy(combined + CROSSMOOL_SM4_GCM_IV_SIZE, ciphertext, plaintext_len);
    memcpy(combined + CROSSMOOL_SM4_GCM_IV_SIZE + plaintext_len, tag, CROSSMOOL_SM4_GCM_TAG_SIZE);

    free(ciphertext);

    /* Base64 编码 */
    ret = crossmool_base64_encode(combined, combined_len, ciphertext_base64);

    free(combined);

    return ret;
}

/**
 * SM4 GCM 模式解密
 * 输入格式：Base64(IV[12字节] + 密文 + Tag[16字节])
 * @param key 密钥（16 字节）
 * @param ciphertext_base64 Base64 编码的（IV + 密文 + Tag）
 * @param plaintext 输出参数，存储解密后的明文
 * @param plaintext_len 输出参数，存储明文长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 plaintext 内存
 */
int crossmool_sm4_decrypt_gcm(
    const unsigned char* key,
    const char* ciphertext_base64,
    unsigned char** plaintext,
    size_t* plaintext_len
) {
    unsigned char* decoded = NULL;
    size_t decoded_len = 0;
    const unsigned char* iv;
    const unsigned char* ciphertext;
    const unsigned char* tag;
    size_t ciphertext_len;
    unsigned char* output = NULL;
    SM4_KEY sm4_key;
    int ret;

    if (key == NULL || ciphertext_base64 == NULL || plaintext == NULL || plaintext_len == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    /* Base64 解码 */
    ret = crossmool_base64_decode(ciphertext_base64, &decoded, &decoded_len);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }

    /* 检查最小长度：IV(12) + Tag(16) = 28 字节，密文可以为 0 字节 */
    if (decoded_len < CROSSMOOL_SM4_GCM_IV_SIZE + CROSSMOOL_SM4_GCM_TAG_SIZE) {
        free(decoded);
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }

    /* 解析 IV + 密文 + Tag */
    iv = decoded;
    ciphertext = decoded + CROSSMOOL_SM4_GCM_IV_SIZE;
    ciphertext_len = decoded_len - CROSSMOOL_SM4_GCM_IV_SIZE - CROSSMOOL_SM4_GCM_TAG_SIZE;
    tag = decoded + CROSSMOOL_SM4_GCM_IV_SIZE + ciphertext_len;

    /* 分配明文缓冲区 */
    output = (unsigned char*)malloc(ciphertext_len > 0 ? ciphertext_len : 1);
    if (output == NULL) {
        free(decoded);
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }

    /* 设置解密密钥并执行 GCM 解密 */
    sm4_set_encrypt_key(&sm4_key, key);
    if (sm4_gcm_decrypt(&sm4_key, iv, CROSSMOOL_SM4_GCM_IV_SIZE,
            NULL, 0, ciphertext, ciphertext_len,
            tag, CROSSMOOL_SM4_GCM_TAG_SIZE, output) != 1) {
        free(output);
        free(decoded);
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }

    free(decoded);

    *plaintext = output;
    *plaintext_len = ciphertext_len;

    return CROSSMOOL_SUCCESS;
}
