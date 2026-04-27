#include "crossmool_util.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Base64 编码表
static const char base64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 解码表
static const int base64_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

/**
 * 判断字符串是否为 Base64 格式
 * @param str 输入字符串
 * @return 是 Base64 格式返回 1，否则返回 0
 */
int crossmool_is_base64_string(const char* str) {
    if (str == NULL || str[0] == '\0') {
        return 0;
    }
    
    size_t len = strlen(str);
    
    // Base64 长度必须是 4 的倍数
    if (len % 4 != 0) {
        return 0;
    }
    
    // 检查每个字符
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        
        // 允许换行符和回车符
        if (c == '\n' || c == '\r' || c == ' ') {
            continue;
        }
        
        // 检查是否为有效的 Base64 字符
        if (c == '=') {
            // 填充符只能出现在末尾
            if (i < len - 2) {
                return 0;
            }
            // 最后一个填充符后面不能有非填充符
            for (size_t j = i + 1; j < len; j++) {
                if (str[j] != '=' && str[j] != '\n' && str[j] != '\r' && str[j] != ' ') {
                    return 0;
                }
            }
        } else {
            int idx = (unsigned char)c;
            if (idx > 127 || base64_decode_table[idx] == -1) {
                return 0;
            }
        }
    }
    
    return 1;
}

/**
 * Base64 编码
 * @param data 输入数据
 * @param data_len 数据长度
 * @param base64_str 输出参数，存储 Base64 编码字符串
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 base64_str 内存
 */
int crossmool_base64_encode(const unsigned char* data, size_t data_len, char** base64_str) {
    if (data == NULL || base64_str == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    // 计算输出长度：每 3 字节输入生成 4 字节输出
    size_t encoded_len = (data_len / 3) * 4 + (data_len % 3 > 0 ? 4 : 0);
    encoded_len += 1;  // +1 for null terminator
    
    *base64_str = (char*)malloc(encoded_len);
    if (*base64_str == NULL) {
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }
    
    size_t i = 0, j = 0;
    size_t remaining = data_len;
    while (remaining > 0) {
        unsigned char b0 = data[i++];
        remaining--;
        
        (*base64_str)[j++] = base64_table[b0 >> 2];
        
        if (remaining > 0) {
            unsigned char b1 = data[i++];
            remaining--;
            (*base64_str)[j++] = base64_table[((b0 & 0x03) << 4) | (b1 >> 4)];
            
            if (remaining > 0) {
                unsigned char b2 = data[i++];
                remaining--;
                (*base64_str)[j++] = base64_table[((b1 & 0x0F) << 2) | (b2 >> 6)];
                (*base64_str)[j++] = base64_table[b2 & 0x3F];
            } else {
                /* Only 2 bytes in this group: 3rd char from b1 low, 4th char = padding */
                (*base64_str)[j++] = base64_table[((b1 & 0x0F) << 2)];
                (*base64_str)[j++] = '=';
            }
        } else {
            /* Only 1 byte in this group: 2nd char from b0 low, 3rd+4th = padding */
            (*base64_str)[j++] = base64_table[(b0 & 0x03) << 4];
            (*base64_str)[j++] = '=';
            (*base64_str)[j++] = '=';
        }
    }
    
    (*base64_str)[j] = '\0';
    
    return CROSSMOOL_SUCCESS;
}

/**
 * Base64 解码
 * @param base64_str Base64 编码字符串
 * @param data 输出参数，存储解码后的数据
 * @param data_len 输出参数，存储数据长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 data 内存
 */
int crossmool_base64_decode(const char* base64_str, unsigned char** data, size_t* data_len) {
    if (base64_str == NULL || data == NULL || data_len == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    size_t str_len = strlen(base64_str);
    
    // 计算有效字符数（排除填充符和空白符）
    size_t valid_chars = 0;
    size_t padding = 0;
    for (size_t i = 0; i < str_len; i++) {
        char c = base64_str[i];
        if (c == '=') {
            padding++;
        } else if (c != '\n' && c != '\r' && c != ' ') {
            valid_chars++;
        }
    }
    
    // 计算输出长度
    *data_len = (valid_chars * 3) / 4 - padding;
    
    *data = (unsigned char*)malloc(*data_len + 1);
    if (*data == NULL) {
        return CROSSMOOL_ERR_MEMORY_ALLOC;
    }
    
    size_t i = 0, j = 0;
    int char_count = 0;
    unsigned char temp[4];
    
    while (i < str_len) {
        char c = base64_str[i++];
        
        // 跳过空白符
        if (c == '\n' || c == '\r' || c == ' ') {
            continue;
        }
        
        // 处理填充符
        if (c == '=') {
            break;
        }
        
        int idx = (unsigned char)c;
        if (idx > 127 || base64_decode_table[idx] == -1) {
            free(*data);
            *data = NULL;
            return CROSSMOOL_ERR_FORMAT_CONVERSION;
        }
        
        temp[char_count++] = (unsigned char)base64_decode_table[idx];
        
        if (char_count == 4) {
            (*data)[j++] = (temp[0] << 2) | (temp[1] >> 4);
            (*data)[j++] = (temp[1] << 4) | (temp[2] >> 2);
            (*data)[j++] = (temp[2] << 6) | temp[3];
            char_count = 0;
        }
    }
    
    // 处理剩余的字符
    if (char_count > 1) {
        (*data)[j++] = (temp[0] << 2) | (temp[1] >> 4);
    }
    if (char_count > 2) {
        (*data)[j++] = (temp[1] << 4) | (temp[2] >> 2);
    }
    
    *data_len = j;
    
    return CROSSMOOL_SUCCESS;
}