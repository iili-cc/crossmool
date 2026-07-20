# crossmool-c

C 语言实现的国密算法（SM2、SM3、SM4）工具库，基于 GmSSL 开发。

## 特性

- **SM2**: 椭圆曲线公钥密码算法（加密/解密/签名/验签）
- **SM3**: 密码杂凑算法
- **SM4**: 分组密码算法（对称加密）
- **完全互通**: 与 Java、C++、Python、JavaScript、Go、Rust 等版本保持完全互通
- **多种编码格式**: 支持 byte[]、HEX、Base64 三种编码格式
- **字符集支持**: 默认 UTF-8，支持其他常用字符集
- **跨平台**: 支持 C20 标准及以上版本，兼容 GCC、Clang/LLVM、MSVC

## 构建要求

- CMake >= 3.20
- vcpkg (用于依赖管理)
- GmSSL >= 2.3.0
- C20 兼容编译器（GCC 10+、Clang 14+、MSVC 2019+）

## 快速开始

### 1. 安装依赖

```bash
# 使用 vcpkg 安装 GmSSL
vcpkg install gmssl

# 或者手动安装 GmSSL
# 参考：https://github.com/guanzhi/GmSSL
```

### 2. 构建项目

```bash
# 创建构建目录
mkdir build && cd build

# 配置项目（使用 vcpkg）
cmake -G "Visual Studio 17 2022" -A x64 .. -DCMAKE_TOOLCHAIN_FILE=[vcpkg 路径]/scripts/buildsystems/vcpkg.cmake

# 或者使用 Ninja
cmake -G Ninja .. -DCMAKE_TOOLCHAIN_FILE=[vcpkg 路径]/scripts/buildsystems/vcpkg.cmake

# 构建
cmake --build . --config Release

# 运行测试
ctest -C Release
```

### 3. 安装

```bash
# 安装到系统
cmake --install . --config Release
```

## 使用示例

### SM2 加密解密

```c
#include <stdio.h>
#include "crossmool.h"

int main(void) {
    // 生成密钥对
    crossmool_sm2_keypair_t* keypair = NULL;
    crossmool_sm2_generate_keypair(&keypair);
    crossmool_sm2_keypair_to_hex(keypair);
    
    printf("Private Key: %s\n", keypair->private_key_hex);
    printf("Public Key: %s\n", keypair->public_key_hex);
    
    // 加密
    const char* message = "Hello, SM2!";
    char* ciphertext_hex = NULL;
    crossmool_sm2_encrypt(message, NULL, keypair->public_key_hex, &ciphertext_hex);
    
    printf("Ciphertext: %s\n", ciphertext_hex);
    
    // 解密
    char* decrypted = NULL;
    crossmool_sm2_decrypt(ciphertext_hex, keypair->private_key_hex, NULL, &decrypted);
    
    printf("Decrypted: %s\n", decrypted);
    
    // 清理
    free(ciphertext_hex);
    free(decrypted);
    crossmool_sm2_keypair_free(keypair);
    
    return 0;
}
```

### SM2 签名验签

```c
// 签名
char* signature_hex = NULL;
crossmool_sm2_sign(message, NULL, keypair->private_key_hex, &signature_hex);

// 验签
int result = crossmool_sm2_verify(message, NULL, signature_hex, keypair->public_key_hex);
if (result == 1) {
    printf("Signature valid!\n");
}

free(signature_hex);
```

### SM3 杂凑

```c
const char* data = "Hello, SM3!";
char* digest_hex = NULL;

crossmool_sm3_digest_str(data, NULL, &digest_hex);
printf("SM3 Digest: %s\n", digest_hex);

free(digest_hex);
```

### SM3 HMAC

```c
const char* key = "secret_key";
const char* data = "Hello, HMAC-SM3!";
char* hmac_hex = NULL;

crossmool_sm3_hmac_str(key, NULL, data, NULL, &hmac_hex);
printf("HMAC: %s\n", hmac_hex);

// 验证
int result = crossmool_sm3_hmac_verify(key, NULL, data, NULL, hmac_hex);

free(hmac_hex);
```

### SM4 加密解密

```c
// 生成密钥
char* key_hex = NULL;
crossmool_sm4_generate_key_hex(&key_hex);

unsigned char key[16];
crossmool_sm4_parse_hex_key(key_hex, key);

// 加密 (GCM 模式，返回 Hex: IV[12] + Ciphertext + Tag[16])
const char* plaintext = "Hello, SM4!";
char* ciphertext_hex = NULL;
crossmool_sm4_encrypt_gcm_str_hex(key, plaintext, &ciphertext_hex);

// 解密
char* decrypted = NULL;
crossmool_sm4_decrypt_gcm_hex_str(key, ciphertext_hex, &decrypted);

printf("Decrypted: %.*s\n", (int)decrypted_len, decrypted);

free(key_hex);
free(ciphertext_hex);
free(decrypted);
```

## API 文档

### SM2 API

- `crossmool_sm2_generate_keypair()`: 生成密钥对
- `crossmool_sm2_encrypt()`: 加密
- `crossmool_sm2_decrypt()`: 解密
- `crossmool_sm2_sign()`: 签名
- `crossmool_sm2_verify()`: 验签
- `crossmool_sm2_encrypt_sign()`: 加密并签名
- `crossmool_sm2_verify_decrypt()`: 验签并解密

### SM3 API

- `crossmool_sm3_digest()`: 杂凑计算
- `crossmool_sm3_hmac()`: HMAC 计算
- `crossmool_sm3_hmac_verify()`: HMAC 验证

### SM4 API

- `crossmool_sm4_generate_key()` / `crossmool_sm4_generate_key_hex()` / `crossmool_sm4_generate_key_base64()`: 生成密钥
- `crossmool_sm4_encrypt_gcm_hex()` / `crossmool_sm4_encrypt_gcm_str_hex()`: GCM 模式加密（Hex）
- `crossmool_sm4_encrypt_gcm_base64()` / `crossmool_sm4_encrypt_gcm_str_base64()`: GCM 模式加密（Base64）
- `crossmool_sm4_decrypt_gcm_hex()` / `crossmool_sm4_decrypt_gcm_hex_str()`: GCM 模式解密（Hex）
- `crossmool_sm4_decrypt_gcm_base64()` / `crossmool_sm4_decrypt_gcm_base64_str()`: GCM 模式解密（Base64）

### 工具 API

- `crossmool_hex_encode/decode()`: HEX 编解码
- `crossmool_base64_encode/decode()`: Base64 编解码
- `crossmool_string_to_bytes()`: 字符串转字节
- `crossmool_bytes_to_string()`: 字节转字符串

## 项目结构

```
c/crossmool/
├── include/          # 头文件
│   ├── crossmool.h       # 主头文件
│   ├── crossmool_error.h # 错误码定义
│   ├── crossmool_util.h  # 工具函数
│   ├── crossmool_sm2.h   # SM2 API
│   ├── crossmool_sm3.h   # SM3 API
│   └── crossmool_sm4.h   # SM4 API
├── src/              # 源代码
│   ├── error.c
│   ├── util_hex.c
│   ├── util_base64.c
│   ├── util_string.c
│   ├── sm2.c
│   ├── sm3.c
│   └── sm4.c
├── tests/            # 测试代码
├── samples/          # 用户快速上手示例
├── cmake/            # CMake 配置文件
├── CMakeLists.txt    # CMake 构建脚本
├── vcpkg.json        # vcpkg 依赖配置
└── README.md         # 本文件
```

## 互通性

本库与以下语言的 crossmool 实现完全互通：

- Java: `java/crossmool/`
- C++: `cpp/crossmool/`
- C#: `csharp/crossmool/`
- Python: `python/crossmool/`
- JavaScript/TypeScript: `javascript/crossmool/`
- Go: `golang/crossmool/`
- Rust: `rust/crossmool/`

所有实现使用相同的：
- SM2 C1C3C2 密文格式
- SM2 签名格式
- SM3 杂凑算法
- 编码格式（HEX/Base64）

## 许可证

GPLv3 License

## 标准发布包结构

crossmool-1.0.0-x64/
├── include/
│   ├── crossmool.h
│   ├── crossmool_error.h
│   ├── crossmool_sm2.h
│   ├── crossmool_sm3.h
│   ├── crossmool_sm4.h
│   └── crossmool_util.h
├── lib/
│   └── crossmool.lib
├── bin/
│   ├── crossmool.dll
│   └── gmssl.dll
└── README.txt

## 贡献



## 联系方式

- 项目地址：https://gitee.com/iilic/crossmool