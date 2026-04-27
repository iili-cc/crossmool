#ifndef CROSSMOOL_ERROR_H
#define CROSSMOOL_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

// 成功状态码
#define CROSSMOOL_SUCCESS  0

// 错误状态码
#define CROSSMOOL_ERR_INVALID_PARAM     -1  // 参数错误
#define CROSSMOOL_ERR_MEMORY_ALLOC      -2  // 内存分配失败
#define CROSSMOOL_ERR_ENCRYPT_DECRYPT   -3  // 加密/解密失败
#define CROSSMOOL_ERR_SIGN_VERIFY       -4  // 签名/验签失败
#define CROSSMOOL_ERR_FORMAT_CONVERSION -5  // 格式转换错误
#define CROSSMOOL_ERR_KEY_INVALID       -6  // 密钥无效
#define CROSSMOOL_ERR_CHARSET_INVALID   -7  // 字符集不支持

/**
 * 获取错误描述字符串
 * @param error_code 错误码
 * @return 错误描述字符串（静态字符串，无需释放）
 */
const char* crossmool_error_string(int error_code);

/**
 * 获取库版本号
 * @return 版本号字符串（格式：major.minor.patch）
 */
const char* crossmool_version(void);

#ifdef __cplusplus
}
#endif

#endif // CROSSMOOL_ERROR_H