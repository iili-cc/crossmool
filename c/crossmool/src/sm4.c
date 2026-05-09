#include "crossmool_sm4.h"
#include "crossmool_util.h"
#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0
#include <gmssl/sm4.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/**
 * 生成 SM4 密钥
 * @param key 输出参数，存储生成的密钥（至少 16 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm4_generate_key(unsigned char* key) {
    int i;
    unsigned int seed;
    
    if (key == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    // 使用系统随机数生成密钥
    // 注意：在生产环境中应使用更安全的随机数生成器
    seed = (unsigned int)time(NULL) ^ (unsigned int)clock();
    
    for (i = 0; i < CROSSMOOL_SM4_KEY_SIZE; i++) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        key[i] = (unsigned char)(seed >> 16);
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
 * PKCS7 填充
 * @param data 数据指针
 * @param data_len 数据长度
 * @param block_size 块大小（SM4 为 16）
 * @return 填充后的数据长度
 */
static size_t pkcs7_pad(unsigned char* data, size_t data_len, size_t block_size) {
    size_t pad_len;
    size_t i;
    
    pad_len = block_size - (data_len % block_size);
    for (i = 0; i < pad_len; i++) {
        data[data_len + i] = (unsigned char)pad_len;
    }
    return data_len + pad_len;
}

/**
 * PKCS7 去填充
 * @param data 数据指针
 * @param data_len 数据长度
 * @return 去填充后的数据长度，失败返回 0
 */
static size_t pkcs7_unpad(const unsigned char* data, size_t data_len) {
    size_t pad_len;
    size_t i;
    
    if (data_len == 0) {
        return 0;
    }
    
    pad_len = data[data_len - 1];
    if (pad_len == 0 || pad_len > 16 || pad_len > data_len) {
        return 0;
    }
    
    // 验证填充
    for (i = 0; i < pad_len; i++) {
        if (data[data_len - 1 - i] != pad_len) {
            return 0;
        }
    }
    
    return data_len - pad_len;
}

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
) {
    size_t padded_len;
    unsigned char* padded_data;
    unsigned char* ciphertext;
    SM4_KEY ctx;
    uint8_t iv[16] = {0};
    int ret;
    
    if (key == NULL || plaintext == NULL || ciphertext_hex == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    // 计算填充后的长度（不传 NULL 指针）
    {
        size_t pad = 16 - (plaintext_len % 16);
        padded_len = plaintext_len + pad;
    }
    if (padded_len == 0) {
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }
    
    // 分配填充缓冲区
    padded_data = (unsigned char*)malloc(padded_len);
    if (padded_data == NULL) {
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }
    
    memcpy(padded_data, plaintext, plaintext_len);
    padded_len = pkcs7_pad(padded_data, plaintext_len, 16);
    
    // 分配密文缓冲区
    ciphertext = (unsigned char*)malloc(padded_len);
    if (ciphertext == NULL) {
        free(padded_data);
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }
    
    // 加密 - ECB 模式：对每个块独立加密
    sm4_set_encrypt_key(&ctx, key);
    for (size_t i = 0; i < padded_len; i += 16) {
        sm4_encrypt(&ctx, padded_data + i, ciphertext + i);
    }
    
    // 转换为 HEX
    ret = crossmool_hex_encode(ciphertext, padded_len, ciphertext_hex);
    
    free(padded_data);
    free(ciphertext);
    
    return ret;
}

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
) {
    unsigned char* ciphertext = NULL;
    size_t ciphertext_len = 0;
    unsigned char* decrypted;
    SM4_KEY ctx;
    uint8_t iv[16] = {0};
    size_t actual_len;
    int ret;
    
    if (key == NULL || ciphertext_hex == NULL || plaintext == NULL || plaintext_len == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    // 解码密文
    ret = crossmool_hex_decode(ciphertext_hex, &ciphertext, &ciphertext_len);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    // 密文长度必须是 16 的倍数
    if (ciphertext_len == 0 || ciphertext_len % 16 != 0) {
        free(ciphertext);
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }
    
    // 分配解密缓冲区
    decrypted = (unsigned char*)malloc(ciphertext_len);
    if (decrypted == NULL) {
        free(ciphertext);
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }
    
    // 解密 - ECB 模式：对每个块独立解密
    sm4_set_decrypt_key(&ctx, key);
    for (size_t i = 0; i < ciphertext_len; i += 16) {
        sm4_decrypt(&ctx, ciphertext + i, decrypted + i);
    }
    
    free(ciphertext);
    
    // 去填充
    actual_len = pkcs7_unpad(decrypted, ciphertext_len);
    if (actual_len == 0) {
        free(decrypted);
        return CROSSMOOL_ERR_ENCRYPT_DECRYPT;
    }
    
    // 分配明文缓冲区
    *plaintext = (unsigned char*)malloc(actual_len);
    if (*plaintext == NULL) {
        free(decrypted);
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }
    
    memcpy(*plaintext, decrypted, actual_len);
    *plaintext_len = actual_len;
    
    free(decrypted);
    
    return CROSSMOOL_SUCCESS;
}