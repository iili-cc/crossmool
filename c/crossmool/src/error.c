#include "crossmool_error.h"
#include <string.h>

// 错误消息定义
static const char* error_messages[] = {
    "Success",                          // 0
    "Invalid parameter",                // -1
    "Memory allocation failed",         // -2
    "Encryption/decryption failed",     // -3
    "Signature verification failed",    // -4
    "Format conversion error",          // -5
    "Invalid key",                      // -6
    "Unsupported charset"               // -7
};

#define NUM_ERROR_MESSAGES (sizeof(error_messages) / sizeof(error_messages[0]))

/**
 * 获取错误描述字符串
 * @param error_code 错误码
 * @return 错误描述字符串（静态字符串，无需释放）
 */
const char* crossmool_error_string(int error_code) {
    if (error_code >= 0 && (size_t)error_code < NUM_ERROR_MESSAGES) {
        return error_messages[error_code];
    }
    if (error_code < 0 && (size_t)-error_code < NUM_ERROR_MESSAGES) {
        return error_messages[-error_code];
    }
    return "Unknown error";
}

/**
 * 获取库版本号
 * @return 版本号字符串（格式：major.minor.patch）
 */
const char* crossmool_version(void) {
#ifdef CROSSMOOL_VERSION_STRING
    return CROSSMOOL_VERSION_STRING;
#else
    return "1.0.0";
#endif
}