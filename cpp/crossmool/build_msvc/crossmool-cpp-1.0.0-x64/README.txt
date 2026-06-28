crossmool-cpp v1.0.0 for Windows x64 (MSVC)
=============================================

C++17 国密算法工具库，基于 GmSSL 实现 SM2/SM3/SM4。

目录结构
--------
  include/       头文件（#include "SM2Util.h" 等）
  lib/           MSVC 导入库（crossmool.lib）
  bin/           动态库（crossmool.dll + 依赖 gmssl.dll）

编译示例
--------
  cl /EHsc /I"include" myapp.cpp /link "lib/crossmool.lib"

运行时
------
  将 bin/ 下的 crossmool.dll 和 gmssl.dll 与你的 .exe 放在同一目录。

API 概览
--------
  SM2Util    密钥生成(Base64/Hex)、加解密、签名验签、encrypt+sign/verify+decrypt 组合
  SM3Util    摘要、HMAC-SM3（支持多种字符串/字节参数重载）
  SM4Util    GCM 模式加解密（Hex/Base64，随机 IV）
  HexUtil    Hex 编解码及格式检测
  Base64Util  Base64 编解码及格式检测
  StringUtil  字符集转换（UTF-8/UTF-16LE/UTF-16BE/GB2312）

技术规格
--------
  SM2  加密输出 C1C3C2 格式（04 前缀），签名使用 SM3-with-ID
  SM4  仅 GCM 模式，IV=12字节，Tag=16字节
  支持 Hex 和 Base64 两种编码

依赖
----
  GmSSL 3.x（bin/gmssl.dll 已内置）

要求
----
  MSVC 2022 (v143) 或更高
  C++17 标准
