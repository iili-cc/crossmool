# C 语言国密工具库 (crossmool-c) 实施待办清单

## 1. 项目基础设置

- [ ] 1. 创建项目目录结构
  - 创建 `c/crossmool/` 目录
  - 创建子目录：`include/`, `src/`, `tests/`, `examples/`
  - 创建 CMake 构建配置文件
  - _需求：10, 17_

- [ ] 2. 配置 CMakeLists.txt
  - 设置项目名为 `crossmool-c`
  - 设置 C 语言标准为 C20
  - 配置 GmSSL 依赖查找
  - 定义库目标（静态库和动态库）
  - 配置头文件安装路径
  - 生成 `crossmool-config.cmake` 文件
  - _需求：10, 17_

- [ ] 3. 配置 vcpkg.json
  - 添加 `gmssl` 依赖
  - 设置项目版本信息
  - 配置支持的平台
  - _需求：17_

## 2. 公共头文件开发

- [ ] 4. 实现 crossmool_error.h
  - 定义错误码常量（CROSSMOOL_SUCCESS, CROSSMOOL_ERR_INVALID_PARAM 等）
  - 实现 `crossmool_error_string()` 函数
  - 实现 `crossmool_version()` 函数
  - _需求：15_

- [ ] 5. 实现 crossmool_util.h
  - 声明格式检测函数（`crossmool_is_hex_string`, `crossmool_is_base64_string`）
  - 声明编解码函数（`crossmool_hex_encode/decode`, `crossmool_base64_encode/decode`）
  - 声明字符串转换函数（`crossmool_string_to_bytes`, `crossmool_bytes_to_string`）
  - 声明清理函数（`crossmool_cleanup`）
  - _需求：9, 8_

- [ ] 6. 实现 crossmool_sm2.h
  - 定义 `crossmool_sm2_keypair_t` 结构体
  - 定义 `crossmool_sm2_cipher_sig_pair_t` 结构体
  - 声明密钥生成函数
  - 声明加密解密函数
  - 声明签名验签函数
  - 声明组合操作函数
  - _需求：1, 2, 3, 7_

- [ ] 7. 实现 crossmool_sm3.h
  - 声明杂凑计算函数
  - 声明 HMAC 相关函数
  - _需求：4, 5_

- [ ] 8. 实现 crossmool_sm4.h
  - 声明密钥生成函数
  - 声明加密解密函数
  - _需求：6_

- [ ] 9. 实现 crossmool.h（主头文件）
  - 包含所有子头文件
  - 提供版本宏定义
  - _需求：10_

## 3. 工具函数实现

- [ ] 10. 实现 util_hex.c
  - 实现 `crossmool_is_hex_string()` 函数
  - 实现 `crossmool_hex_encode()` 函数
  - 实现 `crossmool_hex_decode()` 函数
  - 添加输入验证和错误处理
  - _需求：9, 12_

- [ ] 11. 实现 util_base64.c
  - 实现 `crossmool_is_base64_string()` 函数
  - 实现 `crossmool_base64_encode()` 函数
  - 实现 `crossmool_base64_decode()` 函数
  - 添加输入验证和错误处理
  - _需求：9, 12_

- [ ] 12. 实现 util_string.c
  - 实现 `crossmool_string_to_bytes()` 函数（支持 UTF-8/GBK 等字符集）
  - 实现 `crossmool_bytes_to_string()` 函数
  - 添加字符集验证逻辑
  - _需求：8, 12_

- [ ] 13. 实现 error.c
  - 实现 `crossmool_error_string()` 函数
  - 实现 `crossmool_version()` 函数
  - _需求：15, 10_

- [ ] 14. 编写工具函数单元测试
  - 测试 HEX 编解码正确性
  - 测试 Base64 编解码正确性
  - 测试格式检测函数
  - 测试字符集转换
  - _需求：16_

## 4. SM2 模块实现

- [ ] 15. 实现 sm2.c - 密钥管理
  - 实现 `crossmool_sm2_generate_keypair_base64()` 函数
  - 实现 `crossmool_sm2_generate_keypair_hex()` 函数
  - 实现 `crossmool_sm2_keypair_free()` 函数
  - 使用 GmSSL 的 `sm2_key_generate()` 生成密钥
  - 使用 `sm2_public_key_to_der()` 和 `sm2_private_key_to_der()` 导出密钥
  - _需求：1_

- [ ] 16. 实现 sm2.c - 加密解密
  - 实现 `crossmool_sm2_encrypt()` 函数（C1C3C2 格式）
  - 实现 `crossmool_sm2_encrypt_to_hex()` 函数
  - 实现 `crossmool_sm2_encrypt_to_base64()` 函数
  - 实现 `crossmool_sm2_decrypt()` 函数
  - 实现 `crossmool_sm2_decrypt_to_string()` 函数
  - 使用 GmSSL 的 `sm2_encrypt()` 和 `sm2_decrypt()` 函数
  - 使用 USER_ID = "0123456789ABCDEF"
  - _需求：2, 12_

- [ ] 17. 实现 sm2.c - 签名验签
  - 实现 `crossmool_sm2_sign()` 函数
  - 实现 `crossmool_sm2_sign_to_hex()` 函数
  - 实现 `crossmool_sm2_sign_to_base64()` 函数
  - 实现 `crossmool_sm2_verify()` 函数
  - 使用 GmSSL 的 `sm2_sign()` 和 `sm2_verify()` 函数
  - _需求：3, 12_

- [ ] 18. 实现 sm2.c - 组合操作
  - 实现 `crossmool_sm2_encrypt_sign()` 函数
  - 实现 `crossmool_sm2_verify_decrypt()` 函数
  - 实现 `crossmool_sm2_cipher_sig_pair_free()` 函数
  - _需求：7_

- [ ] 19. 编写 SM2 单元测试
  - 测试密钥生成和格式验证
  - 测试加密解密往返
  - 测试签名验签
  - 测试组合操作
  - _需求：16_

## 5. SM3 模块实现

- [ ] 20. 实现 sm3.c - 杂凑计算
  - 实现 `crossmool_sm3_digest()` 函数
  - 实现 `crossmool_sm3_digest_to_hex()` 函数
  - 实现 `crossmool_sm3_digest_to_base64()` 函数
  - 使用 GmSSL 的 `sm3()` 函数
  - _需求：4_

- [ ] 21. 实现 sm3.c - HMAC
  - 实现 `crossmool_sm3_generate_hmac_key()` 函数
  - 实现 `crossmool_sm3_hmac()` 函数
  - 实现 `crossmool_sm3_hmac_to_hex()` 函数
  - 实现 `crossmool_sm3_hmac_to_base64()` 函数
  - 实现 `crossmool_sm3_hmac_verify()` 函数
  - 使用 GmSSL 的 `hmac_sm3()` 函数
  - _需求：5, 12_

- [ ] 22. 编写 SM3 单元测试
  - 测试杂凑计算正确性
  - 测试 HMAC 计算和验证
  - _需求：16_

## 6. SM4 模块实现

- [ ] 23. 实现 sm4.c
  - 实现 `crossmool_sm4_generate_key()` 函数
  - 实现 `crossmool_sm4_generate_key_hex()` 函数
  - 实现 `crossmool_sm4_parse_hex_key()` 函数
  - 实现 `crossmool_sm4_encrypt_ecb()` 函数（PKCS7 填充）
  - 实现 `crossmool_sm4_decrypt_ecb()` 函数
  - 使用 GmSSL 的 `sm4_encrypt_ecb()` 和 `sm4_decrypt_ecb()` 函数
  - _需求：6, 12_

- [ ] 24. 编写 SM4 单元测试
  - 测试密钥生成
  - 测试加密解密往返
  - _需求：16_

## 7. 互通性测试

- [ ] 25. 实现 test_interop.c
  - 使用 Java 版本生成的测试密钥
  - 测试 SM2 加密互通性（Java 加密 -> C 解密）
  - 测试 SM2 解密互通性（C 加密 -> Java 解密）
  - 测试 SM2 签名互通性（Java 签名 -> C 验签）
  - 测试 SM2 验签互通性（C 签名 -> Java 验签）
  - 测试 SM3 杂凑互通性
  - 测试 SM4 加密互通性
  - _需求：16_

- [ ] 26. 准备互通性测试数据
  - 从 Java 版本导出测试密钥对
  - 生成测试向量（明文、密文、签名）
  - 创建测试数据 JSON 文件
  - _需求：16_

## 8. 示例代码

- [ ] 27. 实现 example_sm2.c
  - 演示密钥对生成
  - 演示加密解密
  - 演示签名验签
  - 演示组合操作
  - _需求：16_

- [ ] 28. 实现 example_sm3.c
  - 演示杂凑计算
  - 演示 HMAC 计算和验证
  - _需求：16_

- [ ] 29. 实现 example_sm4.c
  - 演示密钥生成
  - 演示加密解密
  - _需求：16_

## 9. 文档和构建

- [ ] 30. 编写 README.md
  - 项目介绍
  - 安装说明（vcpkg 安装 GmSSL）
  - 构建说明（CMake 配置和编译）
  - 使用示例
  - API 参考
  - 与 Java 版本的互通性说明
  - _需求：16_

- [ ] 31. 配置跨平台编译支持
  - 测试 GCC 编译
  - 测试 Clang 编译
  - 测试 MSVC 编译
  - 添加编译器特定条件编译
  - _需求：17_

- [ ] 32. 添加安装配置
  - 配置 `install(TARGETS)` 安装库文件
  - 配置头文件安装
  - 生成 pkg-config 文件
  - _需求：17_

## 10. 质量保证

- [ ] 33. 运行所有单元测试
  - 验证所有测试通过
  - 修复发现的缺陷
  - _需求：16_

- [ ] 34. 运行互通性测试
  - 与 Java 版本进行完整互通性验证
  - 确保加密/解密/签名/验签完全互通
  - _需求：16_

- [ ] 35. 代码审查和优化
  - 检查内存泄漏
  - 验证错误处理完整性
  - 优化性能关键路径
  - _需求：11, 13, 14_