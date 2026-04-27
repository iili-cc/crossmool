#include "crossmool_util.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * 判断字符串是否为 HEX 格式
 * @param str 输入字符串
 * @return 是 HEX 格式返回 1，否则返回 0
 */
int crossmool_is_hex_string(const char* str) {
    if (str == NULL || str[0] == '\0') {
        return 0;
    }
    
    // HEX 字符串长度必须为偶数
    size_t len = strlen(str);
    if (len % 2 != 0) {
        return 0;
    }
    
    // 检查每个字符是否为十六进制字符
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)str[i])) {
            return 0;
        }
    }
    
    return 1;
}

/**
 * HEX 编码
 * @param data 输入数据
 * @param data_len 数据长度
 * @param hex_str 输出参数，存储 HEX 编码字符串
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 hex_str 内存
 */
int crossmool_hex_encode(const unsigned char* data, size_t data_len, char** hex_str) {
    size_t hex_len;  // C89: 变量声明必须在代码块开头
    
    if (data == NULL || hex_str == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    // 每个字节需要 2 个十六进制字符
    hex_len = data_len * 2 + 1;  // +1 for null terminator
    
    *hex_str = (char*)malloc(hex_len);
    if (*hex_str == NULL) {
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }
    
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < data_len; i++) {
        (*hex_str)[i * 2] = hex_chars[(data[i] >> 4) & 0x0F];
        (*hex_str)[i * 2 + 1] = hex_chars[data[i] & 0x0F];
    }
    (*hex_str)[hex_len - 1] = '\0';
    
    return CROSSMOOL_SUCCESS;
}

/**
 * HEX 解码
 * @param hex_str HEX 编码字符串
 * @param data 输出参数，存储解码后的数据
 * @param data_len 输出参数，存储数据长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 data 内存
 */
int crossmool_hex_decode(const char* hex_str, unsigned char** data, size_t* data_len) {
    if (hex_str == NULL || data == NULL || data_len == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    size_t str_len = strlen(hex_str);
    if (str_len % 2 != 0) {
        return CROSSMOOL_ERR_FORMAT_CONVERSION;
    }
    
    *data_len = str_len / 2;
    *data = (unsigned char*)malloc(*data_len);
    if (*data == NULL) {
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }
    
    for (size_t i = 0; i < *data_len; i++) {
        int hi = tolower((unsigned char)hex_str[i * 2]);
        int lo = tolower((unsigned char)hex_str[i * 2 + 1]);
        int hi_val, lo_val;
        
        if (hi >= '0' && hi <= '9')      hi_val = hi - '0';
        else if (hi >= 'a' && hi <= 'f') hi_val = hi - 'a' + 10;
        else {
            free(*data); *data = NULL;
            return CROSSMOOL_ERR_FORMAT_CONVERSION;
        }
        
        if (lo >= '0' && lo <= '9')      lo_val = lo - '0';
        else if (lo >= 'a' && lo <= 'f') lo_val = lo - 'a' + 10;
        else {
            free(*data); *data = NULL;
            return CROSSMOOL_ERR_FORMAT_CONVERSION;
        }
        
        (*data)[i] = (unsigned char)((hi_val << 4) | lo_val);
    }
    
    return CROSSMOOL_SUCCESS;
}