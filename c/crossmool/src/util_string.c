#include "crossmool_util.h"
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#define strcasecmp _stricmp
#endif

/**
 * 字符集类型定义 */
typedef enum {
    CHARSET_UTF8,
    CHARSET_UTF16LE,
    CHARSET_UTF16BE,
    CHARSET_ISO88591,
    CHARSET_GB2312,
    CHARSET_UNKNOWN
} CharsetType;

/**
 * 根据字符串名称获取字符集类型
 */
static CharsetType get_charset_type(const char* charset) {
    if (charset == NULL) {
        return CHARSET_UTF8;  // 默认 UTF-8
    }
    
    if (strcasecmp(charset, "UTF-8") == 0 || strcasecmp(charset, "UTF8") == 0) {
        return CHARSET_UTF8;
    } else if (strcasecmp(charset, "UTF-16LE") == 0 || strcasecmp(charset, "UTF16LE") == 0) {
        return CHARSET_UTF16LE;
    } else if (strcasecmp(charset, "UTF-16BE") == 0 || strcasecmp(charset, "UTF16BE") == 0) {
        return CHARSET_UTF16BE;
    } else if (strcasecmp(charset, "ISO-8859-1") == 0 || strcasecmp(charset, "ISO88591") == 0 || 
               strcasecmp(charset, "LATIN1") == 0) {
        return CHARSET_ISO88591;
    } else if (strcasecmp(charset, "GB2312") == 0 || strcasecmp(charset, "GBK") == 0) {
        return CHARSET_GB2312;
    }
    
    return CHARSET_UNKNOWN;
}

/**
 * 字符串转换为字节数组
 * @param str 输入字符串
 * @param charset 字符集名称（NULL 表示使用默认 UTF-8）
 * @param data 输出参数，存储转换后的字节数组
 * @param data_len 输出参数，存储字节数组长度
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 data 内存
 */
int crossmool_string_to_bytes(const char* str, const char* charset, unsigned char** data, size_t* data_len) {
    if (str == NULL || data == NULL || data_len == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    CharsetType type = get_charset_type(charset);
    if (type == CHARSET_UNKNOWN) {
        return CROSSMOOL_ERR_CHARSET_INVALID;
    }
    
    size_t str_len = strlen(str);
    
    switch (type) {
        case CHARSET_UTF8:
        case CHARSET_ISO88591:
            // UTF-8 和 ISO-8859-1 可以直接复制
            *data_len = str_len;
            *data = (unsigned char*)malloc(*data_len);
            if (*data == NULL) {
                return CROSSMOOL_ERR_MEMORY_ALLOC;
            }
            memcpy(*data, str, *data_len);
            break;
            
        case CHARSET_UTF16LE:
            // UTF-16LE: 每个字符 2 字节（小端序）
            *data_len = str_len * 2;
            *data = (unsigned char*)malloc(*data_len);
            if (*data == NULL) {
                return CROSSMOOL_ERR_MEMORY_ALLOC;
            }
            for (size_t i = 0; i < str_len; i++) {
                (*data)[i * 2] = (unsigned char)str[i];
                (*data)[i * 2 + 1] = 0;
            }
            break;
            
        case CHARSET_UTF16BE:
            // UTF-16BE: 每个字符 2 字节（大端序）
            *data_len = str_len * 2;
            *data = (unsigned char*)malloc(*data_len);
            if (*data == NULL) {
                return CROSSMOOL_ERR_MEMORY_ALLOC;
            }
            for (size_t i = 0; i < str_len; i++) {
                (*data)[i * 2] = 0;
                (*data)[i * 2 + 1] = (unsigned char)str[i];
            }
            break;
            
        case CHARSET_GB2312:
            // GB2312 编码转换（简化处理：假设输入已经是 GB2312 编码的字符串）
            // 在实际应用中，可能需要使用 iconv 或其他库进行编码转换
            *data_len = str_len;
            *data = (unsigned char*)malloc(*data_len);
            if (*data == NULL) {
                return CROSSMOOL_ERR_MEMORY_ALLOC;
            }
            memcpy(*data, str, *data_len);
            break;
            
        default:
            return CROSSMOOL_ERR_CHARSET_INVALID;
    }
    
    return CROSSMOOL_SUCCESS;
}

/**
 * 字节数组转换为字符串
 * @param data 输入字节数组
 * @param data_len 字节数组长度
 * @param charset 字符集名称（NULL 表示使用默认 UTF-8）
 * @param str 输出参数，存储转换后的字符串
 * @return 成功返回 0，失败返回负数错误码
 * @note 调用者需调用 free() 释放 str 内存
 */
int crossmool_bytes_to_string(const unsigned char* data, size_t data_len, 
                               const char* charset, char** str) {
    if (data == NULL || str == NULL) {
        return CROSSMOOL_ERR_INVALID_PARAM;
    }
    
    CharsetType type = get_charset_type(charset);
    if (type == CHARSET_UNKNOWN) {
        return CROSSMOOL_ERR_CHARSET_INVALID;
    }
    
    switch (type) {
        case CHARSET_UTF8:
        case CHARSET_ISO88591:
            // UTF-8 和 ISO-8859-1 可以直接复制
            *str = (char*)malloc(data_len + 1);
            if (*str == NULL) {
                return CROSSMOOL_ERR_MEMORY_ALLOC;
            }
            memcpy(*str, data, data_len);
            (*str)[data_len] = '\0';
            break;
            
        case CHARSET_UTF16LE:
            // UTF-16LE: 每 2 字节转换为 1 个字符
            if (data_len % 2 != 0) {
                return CROSSMOOL_ERR_FORMAT_CONVERSION;
            }
            {
                size_t len_utf16le = data_len / 2;
                *str = (char*)malloc(len_utf16le + 1);
                if (*str == NULL) {
                    return CROSSMOOL_ERR_MEMORY_ALLOC;
                }
                for (size_t i = 0; i < len_utf16le; i++) {
                    (*str)[i] = (char)data[i * 2];  // 小端序：低字节在前
                }
                (*str)[len_utf16le] = '\0';
            }
            break;
            
        case CHARSET_UTF16BE:
            // UTF-16BE: 每 2 字节转换为 1 个字符
            if (data_len % 2 != 0) {
                return CROSSMOOL_ERR_FORMAT_CONVERSION;
            }
            {
                size_t len_utf16be = data_len / 2;
                *str = (char*)malloc(len_utf16be + 1);
                if (*str == NULL) {
                    return CROSSMOOL_ERR_MEMORY_ALLOC;
                }
                for (size_t i = 0; i < len_utf16be; i++) {
                    (*str)[i] = (char)data[i * 2 + 1];  // 大端序：高字节在前
                }
                (*str)[len_utf16be] = '\0';
            }
            break;
            
        case CHARSET_GB2312:
            // GB2312 编码转换（简化处理）
            *str = (char*)malloc(data_len + 1);
            if (*str == NULL) {
                return CROSSMOOL_ERR_MEMORY_ALLOC;
            }
            memcpy(*str, data, data_len);
            (*str)[data_len] = '\0';
            break;
            
        default:
            return CROSSMOOL_ERR_CHARSET_INVALID;
    }
    
    return CROSSMOOL_SUCCESS;
}

/**
 * 清理全局资源（可选调用）
 */
void crossmool_cleanup(void) {
    // 当前版本无需清理全局资源
    (void)0;
}