#ifndef CROSSMOOL_H
#define CROSSMOOL_H

/**
 * crossmool-c - C 语言国密算法工具库
 * 
 * 基于 GmSSL 库实现的 SM2、SM3、SM4 国密算法工具
 * 与 Java 版本保持完全互通
 */

// 版本信息
#define CROSSMOOL_VERSION_MAJOR 1
#define CROSSMOOL_VERSION_MINOR 0
#define CROSSMOOL_VERSION_PATCH 0
#define CROSSMOOL_VERSION_STRING "1.0.0"

// 包含所有子头文件
#include "crossmool_error.h"
#include "crossmool_util.h"
#include "crossmool_sm2.h"
#include "crossmool_sm3.h"
#include "crossmool_sm4.h"

#endif // CROSSMOOL_H