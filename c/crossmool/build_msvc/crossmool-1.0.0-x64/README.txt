crossmool-c v1.0.0 for Windows x64 (MSVC)
===========================================

C语言国密算法工具库，基于 GmSSL 实现 SM2/SM3/SM4。

目录结构
--------
  include/       头文件（直接 #include "crossmool.h"）
  lib/           MSVC 导入库（crossmool.lib）
  bin/           动态库（crossmool.dll + 依赖 gmssl.dll）

编译示例
--------
  cl /I"include" myapp.c /link "lib/crossmool.lib"

运行时
------
  将 bin/ 下的 crossmool.dll 和 gmssl.dll 与你的 .exe 放在同一目录。

API 概览
--------
  SM2  密钥生成、加解密、签名验签、encrypt+sign/verify+decrypt 组合
  SM3  摘要、HMAC（支持字符串/字节/HEX/Base64 多种接口）
  SM4  GCM 模式加解密（HEX/Base64 两种编码）
  Util HEX/Base64编解码、字符集转换、格式检测

技术规格
--------
  SM2  加密输出 C1C3C2 格式，签名使用 SM3-with-ID
  SM4  仅 GCM 模式，IV=12字节，Tag=16字节
  支持 HEX 和 Base64 两种编码

依赖
----
  GmSSL 3.x（bin/gmssl.dll 已内置，无需单独安装）

更多
----
  https://github.com/your-org/crossmool
