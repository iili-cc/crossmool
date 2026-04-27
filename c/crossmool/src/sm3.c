#include "crossmool_sm3.h"
#include "crossmool_util.h"
#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0
#include <gmssl/sm3.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

#define SM3_DIGEST_SIZE 32  // SM3 杂凑值长度（32 字节）

/**
 * SM3 杂凑计算（返回字节数组）
 * @param data 输入数据
 * @param data_len 数据长度
 * @param digest 输出参数，存储杂凑值（至少 32 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm3_digest(const unsigned char* data, size_t data_len, unsigned char* digest) {
    if (data == NULL || digest == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, data_len);
    sm3_finish(&ctx, digest);
    
    return CROSSMOOL_SUCCESS;
}

/**
 * SM3 杂凑计算（返回 HEX 字符串）
 * @param data 输入数据
 * @param data_len 数据长度
 * @param digest_hex 输出参数，存储 HEX 编码的杂凑值
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 digest_hex 内存
 */
int crossmool_sm3_digest_to_hex(const unsigned char* data, size_t data_len, char** digest_hex) {
    if (data == NULL || digest_hex == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    unsigned char digest[SM3_DIGEST_SIZE];
    int ret = crossmool_sm3_digest(data, data_len, digest);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    return crossmool_hex_encode(digest, SM3_DIGEST_SIZE, digest_hex);
}

/**
 * SM3 杂凑计算（字符串输入，返回 HEX 字符串）
 * @param str 输入字符串
 * @param charset 字符集名称（NULL 表示使用默认 UTF-8）
 * @param digest_hex 输出参数，存储 HEX 编码的杂凑值
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 digest_hex 内存
 */
int crossmool_sm3_digest_str(const char* str, const char* charset, char** digest_hex) {
    if (str == NULL || digest_hex == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    unsigned char* data = NULL;
    size_t data_len = 0;
    
    int ret = crossmool_string_to_bytes(str, charset, &data, &data_len);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    ret = crossmool_sm3_digest_to_hex(data, data_len, digest_hex);
    
    free(data);
    
    return ret;
}

/**
 * SM3 杂凑计算（字符串输入，返回 Base64 字符串）
 * @param str 输入字符串
 * @param charset 字符集名称（NULL 表示使用默认 UTF-8）
 * @param digest_base64 输出参数，存储 Base64 编码的杂凑值
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 digest_base64 内存
 */
int crossmool_sm3_digest_str_to_base64(const char* str, const char* charset, char** digest_base64) {
    if (str == NULL || digest_base64 == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    unsigned char* data = NULL;
    size_t data_len = 0;
    
    int ret = crossmool_string_to_bytes(str, charset, &data, &data_len);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    unsigned char digest[SM3_DIGEST_SIZE];
    ret = crossmool_sm3_digest(data, data_len, digest);
    free(data);
    
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    ret = crossmool_base64_encode(digest, SM3_DIGEST_SIZE, digest_base64);
    
    return ret;
}

/**
 * HMAC-SM3 计算（返回字节数组）
 * @param key HMAC 密钥
 * @param key_len 密钥长度
 * @param data 输入数据
 * @param data_len 数据长度
 * @param hmac 输出参数，存储 HMAC 值（至少 32 字节）
 * @return 成功返回 0，失败返回负数错误码
 */
int crossmool_sm3_hmac(const unsigned char* key, size_t key_len,
                       const unsigned char* data, size_t data_len,
                       unsigned char* hmac) {
    if (key == NULL || data == NULL || hmac == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    SM3_HMAC_CTX ctx;
    sm3_hmac_init(&ctx, key, key_len);
    sm3_hmac_update(&ctx, data, data_len);
    sm3_hmac_finish(&ctx, hmac);
    
    return CROSSMOOL_SUCCESS;
}

/**
 * HMAC-SM3 计算（返回 HEX 字符串）
 * @param key_hex HEX 编码的 HMAC 密钥
 * @param data 输入数据
 * @param data_len 数据长度
 * @param hmac_hex 输出参数，存储 HEX 编码的 HMAC 值
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 hmac_hex 内存
 */
int crossmool_sm3_hmac_hex(const char* key_hex, const unsigned char* data, size_t data_len, char** hmac_hex) {
    if (key_hex == NULL || data == NULL || hmac_hex == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    unsigned char* key = NULL;
    size_t key_len = 0;
    
    int ret = crossmool_hex_decode(key_hex, &key, &key_len);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    unsigned char hmac[SM3_DIGEST_SIZE];
    ret = crossmool_sm3_hmac(key, key_len, data, data_len, hmac);
    free(key);
    
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    ret = crossmool_hex_encode(hmac, SM3_DIGEST_SIZE, hmac_hex);
    
    return ret;
}

/**
 * HMAC-SM3 计算（字符串输入，返回 HEX 字符串）
 * @param key_str HMAC 密钥字符串
 * @param charset 密钥字符集（NULL 表示使用默认 UTF-8）
 * @param data_str 输入数据字符串
 * @param data_charset 数据字符集（NULL 表示使用默认 UTF-8）
 * @param hmac_hex 输出参数，存储 HEX 编码的 HMAC 值
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 hmac_hex 内存
 */
int crossmool_sm3_hmac_str(const char* key_str, const char* charset,
                           const char* data_str, const char* data_charset,
                           char** hmac_hex) {
    if (key_str == NULL || data_str == NULL || hmac_hex == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    unsigned char* key = NULL;
    size_t key_len = 0;
    unsigned char* data = NULL;
    size_t data_len = 0;
    
    int ret = crossmool_string_to_bytes(key_str, charset, &key, &key_len);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    ret = crossmool_string_to_bytes(data_str, data_charset, &data, &data_len);
    if (ret != CROSSMOOL_SUCCESS) {
        free(key);
        return ret;
    }
    
    unsigned char hmac[SM3_DIGEST_SIZE];
    ret = crossmool_sm3_hmac(key, key_len, data, data_len, hmac);
    free(key);
    free(data);
    
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }
    
    ret = crossmool_hex_encode(hmac, SM3_DIGEST_SIZE, hmac_hex);
    
    return ret;
}

/**
 * SM3 杂凑（字节数组输入，返回 Base64 字符串）
 */
int crossmool_sm3_digest_to_base64(const unsigned char* data, size_t data_len, char** digest_base64) {
    if (data == NULL || digest_base64 == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    unsigned char digest[SM3_DIGEST_SIZE];
    int ret = crossmool_sm3_digest(data, data_len, digest);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }

    return crossmool_base64_encode(digest, SM3_DIGEST_SIZE, digest_base64);
}

/**
 * 生成 HMAC-SM3 密钥
 * @param key_length 密钥长度（字节，建议 ≥ 32）
 * @param key 输出参数，存储生成的密钥
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 key 内存
 */
int crossmool_sm3_generate_hmac_key(size_t key_length, unsigned char** key) {
    if (key == NULL || key_length == 0) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    unsigned char* buf = (unsigned char*)malloc(key_length);
    if (buf == NULL) {
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }

    /* 使用 time/clock 混合作为简易随机源（生产环境应使用 BCryptGenRandom 等） */
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)clock();
    for (size_t i = 0; i < key_length; i++) {
        seed = (seed * 1103515245u + 12345u) & 0x7fffffffu;
        buf[i] = (unsigned char)(seed >> 16);
    }

    *key = buf;
    return CROSSMOOL_SUCCESS;
}

/**
 * HMAC-SM3（字符串接口，返回 HEX）
 * key / data 均视为 UTF-8 字符串处理
 */
int crossmool_sm3_hmac_to_hex(const char* key, const char* data, char** mac_hex) {
    if (key == NULL || data == NULL || mac_hex == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    return crossmool_sm3_hmac_str(key, NULL, data, NULL, mac_hex);
}

/**
 * HMAC-SM3（字符串接口，返回 Base64）
 * key / data 均视为 UTF-8 字符串处理
 */
int crossmool_sm3_hmac_to_base64(const char* key, const char* data, char** mac_base64) {
    if (key == NULL || data == NULL || mac_base64 == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    /* 先计算 HEX，再解码为字节，再 Base64 编码 */
    char* hmac_hex = NULL;
    int ret = crossmool_sm3_hmac_str(key, NULL, data, NULL, &hmac_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }

    unsigned char* hmac_bytes = NULL;
    size_t hmac_len = 0;
    ret = crossmool_hex_decode(hmac_hex, &hmac_bytes, &hmac_len);
    free(hmac_hex);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }

    ret = crossmool_base64_encode(hmac_bytes, hmac_len, mac_base64);
    free(hmac_bytes);
    return ret;
}

/**
 * HMAC-SM3 验证（5 参数字符串接口）
 * @param key      密钥字符串
 * @param charset  密钥字符集（NULL 表示 UTF-8）
 * @param data     数据字符串
 * @param data_charset 数据字符集（NULL 表示 UTF-8）
 * @param received_mac 接收到的 HMAC（HEX 或 Base64）
 * @return 验证成功返回 1，失败返回 0，错误返回负数
 */
int crossmool_sm3_hmac_verify(
    const char* key,
    const char* charset,
    const char* data,
    const char* data_charset,
    const char* received_mac) {

    if (key == NULL || data == NULL || received_mac == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }

    /* 计算 HMAC（HEX 格式） */
    char* computed_hmac = NULL;
    int ret = crossmool_sm3_hmac_str(key, charset, data, data_charset, &computed_hmac);
    if (ret != CROSSMOOL_SUCCESS) {
        return ret;
    }

    int result;

    /* received_mac 可能是 HEX 或 Base64，优先判断 HEX */
    if (crossmool_is_hex_string(received_mac)) {
        result = (strcasecmp(computed_hmac, received_mac) == 0) ? 1 : 0;
    } else {
        unsigned char* mac_bytes = NULL;
        size_t mac_len = 0;
        ret = crossmool_base64_decode(received_mac, &mac_bytes, &mac_len);
        if (ret != CROSSMOOL_SUCCESS) {
            free(computed_hmac);
            return ret;
        }
        char* mac_hex = NULL;
        ret = crossmool_hex_encode(mac_bytes, mac_len, &mac_hex);
        free(mac_bytes);
        if (ret != CROSSMOOL_SUCCESS) {
            free(computed_hmac);
            return ret;
        }
        result = (strcasecmp(computed_hmac, mac_hex) == 0) ? 1 : 0;
        free(mac_hex);
    }

    free(computed_hmac);
    return result;
}