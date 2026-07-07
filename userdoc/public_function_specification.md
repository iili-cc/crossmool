# Crossmool 公有函数接口规范

> 本文档为 Crossmool 跨语言国密工具集（SM2 / SM3 / SM4）的公有函数接口规范。
> 涵盖 8 种编程语言实现：C、C++、C#、Java、Python、Go、Rust、JavaScript。
>
> **版本**: v1.0 | **文档日期**: 2026-06-29

---

## 目录

- [1. 概述](#1-概述)
- [2. 通用约定](#2-通用约定)
- [3. C 语言接口](#3-c-语言接口)
  - [3.1 SM2](#31-c--sm2)
  - [3.2 SM3](#32-c--sm3)
  - [3.3 SM4](#33-c--sm4)
  - [3.4 工具函数](#34-c--工具函数)
- [4. C++ 语言接口](#4-c-语言接口)
  - [4.1 SM2Util](#41-c--sm2util)
  - [4.2 SM3Util](#42-c--sm3util)
  - [4.3 SM4Util](#43-c--sm4util)
  - [4.4 工具类](#44-c--工具类)
- [5. C# 语言接口](#5-c-语言接口)
  - [5.1 SM2Util](#51-c--sm2util)
  - [5.2 SM3Util](#52-c--sm3util)
  - [5.3 SM4Util](#53-c--sm4util)
  - [5.4 EncodingUtils](#54-encodingutils)
- [6. Java 语言接口](#6-java-语言接口)
  - [6.1 SM2Util](#61-java--sm2util)
  - [6.2 SM3Util](#62-java--sm3util)
  - [6.3 SM4Util](#63-java--sm4util)
  - [6.4 工具类](#64-java--工具类)
- [7. Python 语言接口](#7-python-语言接口)
  - [7.1 SM2Util](#71-python--sm2util)
  - [7.2 SM3Util](#72-python--sm3util)
  - [7.3 SM4Util](#73-python--sm4util)
  - [7.4 辅助函数](#74-python--辅助函数)
- [8. Go 语言接口](#8-go-语言接口)
  - [8.1 SM2](#81-go--sm2)
  - [8.2 SM3](#82-go--sm3)
  - [8.3 SM4](#83-go--sm4)
  - [8.4 工具函数](#84-go--工具函数)
- [9. Rust 语言接口](#9-rust-语言接口)
  - [9.1 SM2 模块](#91-rust--sm2-模块)
  - [9.2 SM3 模块](#92-rust--sm3-模块)
  - [9.3 SM4 模块](#93-rust--sm4-模块)
  - [9.4 Encoding 模块](#94-rust--encoding-模块)
- [10. JavaScript/TypeScript 语言接口](#10-javascripttypescript-语言接口)
  - [10.1 SM2Util](#101-js--sm2util)
  - [10.2 SM3Util](#102-js--sm3util)
  - [10.3 SM4Util](#103-js--sm4util)
  - [10.4 工具函数](#104-js--工具函数)
- [附录 A: 错误码参考](#附录-a-错误码参考)
- [附录 B: 数据格式说明](#附录-b-数据格式说明)

---

## 1. 概述

Crossmool 是一个基于国密算法（SM2 / SM3 / SM4）的跨语言工具集，旨在让应用软件开发人员可以**直接调用工具类或函数**，无需关心 mode、encode 模式、跨语言互通性等底层细节。

### 核心设计原则

- **一致的 API 风格**：所有语言提供相同概念的方法（加密/解密、签名/验签、摘要/HMAC）
- **自动格式检测**：密钥和密文输入自动识别 HEX 或 Base64 编码
- **跨语言互通**：所有语言共享统一的数据格式，确保互相可解码
- **开箱即用**：默认参数已设定，无需额外配置

### 算法实现

| 算法 | 用途 | 关键参数 |
|------|------|----------|
| SM2 | 非对称加密/签名 | C1C3C2 格式, USER_ID = "1234567812345678" |
| SM3 | 哈希摘要 / HMAC | 输出 32 字节 |
| SM4 | 对称加密 | GCM 模式, IV=12字节, Tag=16字节 |

---

## 2. 通用约定

### 2.1 编码格式

- **HEX**：十六进制小写字符串（如 `04a1b2...`）
- **Base64**：标准 Base64 编码
- 各语言库均提供自动检测，支持 HEX 和 Base64 混合输入

### 2.2 密钥格式

| 密钥类型 | 编码格式 |
|----------|----------|
| SM2 公钥 | X.509 SubjectPublicKeyInfo DER |
| SM2 私钥 | PKCS#8 PrivateKeyInfo DER |
| SM4 密钥 | 16 字节原始密钥 |

### 2.3 输出格式

| 操作 | 默认输出 | 可选输出 |
|------|----------|----------|
| SM2 加密 | HEX(C1C3C2) | Base64(C1C3C2) |
| SM2 签名 | HEX(DER) | Base64(DER) |
| SM3 摘要 | HEX(32字节) | Base64(32字节) |
| SM4 GCM 加密 | HEX(IV[12]+密文+Tag[16]) | Base64(IV[12]+密文+Tag[16]) |

### 2.4 字符集

- 默认字符集：**UTF-8**
- 明文/密文字符串均以 UTF-8 编码处理

---

## 3. C 语言接口

**头文件位置**: `c/crossmool/include/`  
**链接库**: `libcrossmool` (基于 GmSSL)

### 3.1 C — SM2

#### 3.1.1 密钥生成

##### `crossmool_sm2_generate_keypair`

生成 SM2 密钥对（指针模式，自动分配内存）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_generate_keypair(crossmool_sm2_keypair_t** keypair)` |
| **入参** | `keypair` — 输出参数，指向密钥对指针的指针 |
| **出参** | `*keypair` — 生成的密钥对结构体 |
| **返回值** | 成功返回 0，失败返回负数错误码 |
| **注意** | 调用者需调用 `crossmool_sm2_keypair_free()` 释放内存 |

##### `crossmool_sm2_generate_keypair_hex`

生成 SM2 密钥对（HEX 编码，直接结构体）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_generate_keypair_hex(crossmool_sm2_keypair_t* keypair)` |
| **入参** | `keypair` — 输出参数，存储生成的密钥对 |
| **返回值** | 成功返回 0，失败返回负数错误码 |

##### `crossmool_sm2_generate_keypair_base64`

生成 SM2 密钥对（Base64 编码，直接结构体）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_generate_keypair_base64(crossmool_sm2_keypair_t* keypair)` |
| **入参** | `keypair` — 输出参数，存储生成的密钥对 |
| **返回值** | 成功返回 0，失败返回负数错误码 |

##### `crossmool_sm2_keypair_to_hex`

将密钥对转换为 HEX 格式（填充 `private_key_hex` / `public_key_hex` 字段）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_keypair_to_hex(crossmool_sm2_keypair_t* keypair)` |
| **入参** | `keypair` — 已生成的密钥对 |
| **返回值** | 成功返回 0，失败返回负数错误码 |

##### `crossmool_sm2_keypair_to_base64`

将密钥对转换为 Base64 格式（填充 `private_key_base64` / `public_key_base64` 字段）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_keypair_to_base64(crossmool_sm2_keypair_t* keypair)` |
| **入参** | `keypair` — 已生成的密钥对 |
| **返回值** | 成功返回 0，失败返回负数错误码 |

##### `crossmool_sm2_keypair_free`

释放密钥对内存。

| 字段 | 描述 |
|------|------|
| **签名** | `void crossmool_sm2_keypair_free(crossmool_sm2_keypair_t* keypair)` |
| **入参** | `keypair` — 要释放的密钥对指针 |

**结构体定义**：

```c
typedef struct {
    char* private_key;          // 原始私钥 (Base64 或 HEX)
    char* public_key;           // 原始公钥 (Base64 或 HEX)
    char* private_key_hex;      // HEX 格式私钥
    char* public_key_hex;       // HEX 格式公钥
    char* private_key_base64;   // Base64 格式私钥
    char* public_key_base64;    // Base64 格式公钥
} crossmool_sm2_keypair_t;

typedef struct {
    char* ciphertext;           // 密文 (与加密时格式一致)
    char* signature;            // 签名 (与签名时格式一致)
    char* ciphertext_hex;       // HEX 格式密文
    char* signature_hex;        // HEX 格式签名
    char* ciphertext_base64;    // Base64 格式密文
    char* signature_base64;     // Base64 格式签名
} crossmool_sm2_cipher_sig_pair_t;
```

**调用示例**：

```c
#include "crossmool_sm2.h"

// 生成密钥对
crossmool_sm2_keypair_t* keypair = NULL;
int ret = crossmool_sm2_generate_keypair(&keypair);
if (ret == 0) {
    printf("Public key: %s\n", keypair->public_key);
    printf("Private key: %s\n", keypair->private_key);
    crossmool_sm2_keypair_free(keypair);
}
```

---

#### 3.1.2 加密 / 解密

##### `crossmool_sm2_encrypt`

SM2 加密（字符串输入，输出 HEX 密文）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_encrypt(const char* content, const char* charset, const char* public_key, char** ciphertext_hex)` |
| **入参** | `content` — 明文字符串（C 字符串，null 结尾） |
| | `charset` — 字符集（NULL 表示 UTF-8） |
| | `public_key` — 公钥（支持 HEX 或 Base64） |
| **出参** | `ciphertext_hex` — HEX 格式密文 |
| **返回值** | 成功返回 0，失败返回负数错误码 |
| **注意** | 调用者需调用 `free()` 释放 `ciphertext_hex` |

##### `crossmool_sm2_decrypt`

SM2 解密（自动检测格式，输出字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_decrypt(const char* ciphertext, const char* private_key, const char* charset, char** plaintext_str)` |
| **入参** | `ciphertext` — 密文（HEX 或 Base64 字符串） |
| | `private_key` — 私钥（支持 HEX 或 Base64） |
| | `charset` — 字符集（NULL 表示 UTF-8） |
| **出参** | `plaintext_str` — 明文字符串 |
| **返回值** | 成功返回 0，失败返回负数错误码 |
| **注意** | 调用者需调用 `free()` 释放 `plaintext_str` |

##### `crossmool_sm2_encrypt_bytes`

SM2 加密（字节数组输入，返回字节数组）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_encrypt_bytes(const unsigned char* content, size_t content_len, const char* public_key, unsigned char** ciphertext, size_t* ciphertext_len)` |
| **入参** | `content` — 明文数据, `content_len` — 明文长度 |
| | `public_key` — 公钥 |
| **出参** | `ciphertext` — 密文字节, `ciphertext_len` — 密文长度 |
| **返回值** | 成功返回 0，失败返回负数错误码 |

##### `crossmool_sm2_encrypt_to_hex`

SM2 加密（字节数组输入，返回 HEX 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_encrypt_to_hex(const unsigned char* content, size_t content_len, const char* charset, const char* public_key, char** ciphertext_hex)` |

##### `crossmool_sm2_encrypt_to_base64`

SM2 加密（字节数组输入，返回 Base64 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_encrypt_to_base64(const unsigned char* content, size_t content_len, const char* charset, const char* public_key, char** ciphertext_base64)` |

##### `crossmool_sm2_decrypt_bytes`

SM2 解密（返回字节数组）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_decrypt_bytes(const char* ciphertext, const char* private_key, unsigned char** plaintext, size_t* plaintext_len)` |

##### `crossmool_sm2_decrypt_to_string`

SM2 解密并转为字符串。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_decrypt_to_string(const char* ciphertext, const char* private_key, const char* charset, char** plaintext_str)` |

**调用示例**：

```c
#include "crossmool_sm2.h"

// 加密
char* ciphertext_hex = NULL;
int ret = crossmool_sm2_encrypt("Hello, SM2!", NULL, public_key_hex, &ciphertext_hex);
if (ret == 0) {
    printf("Ciphertext: %s\n", ciphertext_hex);

    // 解密
    char* plaintext = NULL;
    ret = crossmool_sm2_decrypt(ciphertext_hex, private_key, NULL, &plaintext);
    if (ret == 0) {
        printf("Plaintext: %s\n", plaintext);
        free(plaintext);
    }
    free(ciphertext_hex);
}
```

---

#### 3.1.3 签名 / 验签

##### `crossmool_sm2_sign`

SM2 签名（字符串输入，输出 HEX 签名）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_sign(const char* content, const char* charset, const char* private_key, char** signature_hex)` |
| **入参** | `content` — 待签名数据 |
| | `charset` — 字符集（NULL 表示 UTF-8） |
| | `private_key` — 私钥（HEX 或 Base64） |
| **出参** | `signature_hex` — HEX 格式签名 |
| **返回值** | 成功返回 0，失败返回负数错误码 |
| **注意** | 调用者需调用 `free()` 释放 `signature_hex` |

##### `crossmool_sm2_verify`

SM2 验签。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_verify(const char* content, const char* charset, const char* signature, const char* public_key)` |
| **入参** | `content` — 原始数据, `charset` — 字符集 |
| | `signature` — 签名（HEX 或 Base64） |
| | `public_key` — 公钥（HEX 或 Base64） |
| **返回值** | 验证成功返回 1，失败返回 0，错误返回负数 |

##### `crossmool_sm2_sign_bytes`

SM2 签名（字节数组输入，返回字节数组）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_sign_bytes(const unsigned char* content, size_t content_len, const char* private_key, unsigned char** signature, size_t* signature_len)` |

##### `crossmool_sm2_sign_to_hex` / `crossmool_sm2_sign_to_base64`

字节数组输入，返回 HEX 或 Base64 签名。

##### `crossmool_sm2_verify_bytes`

字节数组验签。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_verify_bytes(const unsigned char* content, size_t content_len, const char* signature, const char* public_key)` |

---

#### 3.1.4 加密签名组合 / 验签解密

##### `crossmool_sm2_encrypt_sign`

加密并签名（字符串输入，输出 HEX 密文和签名）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_encrypt_sign(const char* content, const char* charset, const char* enc_public_key, const char* sign_private_key, crossmool_sm2_cipher_sig_pair_t** result)` |
| **入参** | `content` — 明文, `charset` — 字符集 |
| | `enc_public_key` — 加密公钥 |
| | `sign_private_key` — 签名私钥 |
| **出参** | `result` — 密文签名对（指针） |
| **返回值** | 成功返回 0，失败返回负数错误码 |
| **注意** | 调用者需调用 `crossmool_sm2_cipher_sig_pair_free()` 释放 |

##### `crossmool_sm2_verify_decrypt`

验签并解密（输出明文字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_verify_decrypt(const char* ciphertext, const char* signature, const char* sign_public_key, const char* dec_private_key, const char* charset, char** plaintext)` |
| **入参** | `ciphertext` — 密文, `signature` — 签名 |
| | `sign_public_key` — 验签公钥 |
| | `dec_private_key` — 解密私钥 |
| | `charset` — 字符集（NULL 表示 UTF-8） |
| **出参** | `plaintext` — 明文字符串 |
| **返回值** | 成功返回 0，失败返回负数错误码 |

##### `crossmool_sm2_encrypt_sign_ex`

加密签名（扩展版，支持 HEX/Base64 输出选择）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm2_encrypt_sign_ex(const unsigned char* content, size_t content_len, const char* charset, const char* enc_public_key, const char* sign_private_key, int to_base64, crossmool_sm2_cipher_sig_pair_t* result)` |

##### `crossmool_sm2_cipher_sig_pair_free`

释放密文签名对内存。

| 字段 | 描述 |
|------|------|
| **签名** | `void crossmool_sm2_cipher_sig_pair_free(crossmool_sm2_cipher_sig_pair_t* pair)` |

---

### 3.2 C — SM3

**常量**：`CROSSMOOL_SM3_DIGEST_SIZE = 32`

#### 3.2.1 杂凑

##### `crossmool_sm3_digest`

SM3 杂凑（字节数组输入，返回字节数组）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_digest(const unsigned char* data, size_t data_len, unsigned char* digest)` |
| **入参** | `data` — 输入数据, `data_len` — 数据长度 |
| **出参** | `digest` — 杂凑值（至少 32 字节） |
| **返回值** | 成功返回 0，失败返回负数错误码 |

##### `crossmool_sm3_digest_to_hex`

SM3 杂凑（字节数组输入，返回 HEX 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_digest_to_hex(const unsigned char* data, size_t data_len, char** digest_hex)` |
| **注意** | 调用者需调用 `free()` 释放 `digest_hex` |

##### `crossmool_sm3_digest_to_base64`

SM3 杂凑（字节数组输入，返回 Base64 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_digest_to_base64(const unsigned char* data, size_t data_len, char** digest_base64)` |

##### `crossmool_sm3_digest_str`

SM3 杂凑（字符串输入，返回 HEX 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_digest_str(const char* str, const char* charset, char** digest_hex)` |
| **入参** | `str` — 输入字符串, `charset` — 字符集（NULL 表示 UTF-8） |

##### `crossmool_sm3_digest_str_to_base64`

SM3 杂凑（字符串输入，返回 Base64 字符串）。

**调用示例**：

```c
#include "crossmool_sm3.h"

unsigned char data[] = "Hello, SM3!";
unsigned char digest[32];
crossmool_sm3_digest(data, strlen((char*)data), digest);

// 或直接对字符串杂凑
char* digest_hex = NULL;
crossmool_sm3_digest_str("Hello, SM3!", NULL, &digest_hex);
printf("SM3: %s\n", digest_hex);
free(digest_hex);
```

---

#### 3.2.2 HMAC-SM3

##### `crossmool_sm3_generate_hmac_key`

生成 HMAC 密钥。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_generate_hmac_key(size_t key_length, unsigned char** key)` |
| **入参** | `key_length` — 密钥长度（至少 32 字节） |
| **出参** | `key` — 生成的密钥 |
| **注意** | 调用者需调用 `free()` 释放 `key` |

##### `crossmool_sm3_hmac`

HMAC-SM3（字节数组输入，返回字节数组）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_hmac(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, unsigned char* mac)` |
| **入参** | `key` — HMAC 密钥, `key_len` — 密钥长度 |
| | `data` — 输入数据, `data_len` — 数据长度 |
| **出参** | `mac` — HMAC 值（至少 32 字节） |

##### `crossmool_sm3_hmac_hex`

HMAC-SM3（HEX 密钥 + 字节数据，返回 HEX 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_hmac_hex(const char* key_hex, const unsigned char* data, size_t data_len, char** hmac_hex)` |

##### `crossmool_sm3_hmac_str`

HMAC-SM3（字符串密钥和数据，返回 HEX 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_hmac_str(const char* key_str, const char* charset, const char* data_str, const char* data_charset, char** hmac_hex)` |

##### `crossmool_sm3_hmac_to_hex` / `crossmool_sm3_hmac_to_base64`

字符串接口，返回 HEX 或 Base64 HMAC。

##### `crossmool_sm3_hmac_verify`

HMAC 验证。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm3_hmac_verify(const char* key, const char* charset, const char* data, const char* data_charset, const char* received_mac)` |
| **返回值** | 验证成功返回 1，失败返回 0，错误返回负数 |

---

### 3.3 C — SM4

**常量**：

| 常量 | 值 | 含义 |
|------|-----|------|
| `CROSSMOOL_SM4_KEY_SIZE` | 16 | 密钥长度（字节） |
| `CROSSMOOL_SM4_GCM_IV_SIZE` | 12 | GCM IV 长度（字节） |
| `CROSSMOOL_SM4_GCM_TAG_SIZE` | 16 | GCM Tag 长度（字节） |

#### 3.3.1 密钥管理

##### `crossmool_sm4_generate_key`

生成 SM4 密钥。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm4_generate_key(unsigned char* key)` |
| **入参** | `key` — 输出参数，存储密钥（至少 16 字节） |
| **返回值** | 成功返回 0，失败返回负数错误码 |

##### `crossmool_sm4_generate_key_hex`

生成 SM4 密钥（返回 HEX 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm4_generate_key_hex(char** key_hex)` |
| **注意** | 调用者需调用 `free()` 释放 `key_hex` |

##### `crossmool_sm4_parse_hex_key`

解析 HEX 密钥字符串。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm4_parse_hex_key(const char* hex_key, unsigned char* key)` |
| **入参** | `hex_key` — HEX 编码的密钥 |
| **出参** | `key` — 解析后的密钥（至少 16 字节） |

##### `crossmool_sm4_generate_iv`

生成随机 IV（12 字节）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm4_generate_iv(unsigned char* iv)` |

#### 3.3.2 GCM 加密/解密

##### `crossmool_sm4_encrypt_gcm_hex` ⭐ 推荐

SM4 GCM 加密（返回 HEX 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm4_encrypt_gcm_hex(const unsigned char* key, const unsigned char* plaintext, size_t plaintext_len, char** ciphertext_hex)` |
| **入参** | `key` — 密钥（16 字节） |
| | `plaintext` — 明文数据, `plaintext_len` — 明文长度 |
| **出参** | `ciphertext_hex` — HEX(IV[12]+密文+Tag[16]) |
| **注意** | 调用者需调用 `free()` 释放 `ciphertext_hex` |

##### `crossmool_sm4_encrypt_gcm_base64`

SM4 GCM 加密（返回 Base64 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm4_encrypt_gcm_base64(const unsigned char* key, const unsigned char* plaintext, size_t plaintext_len, char** ciphertext_base64)` |

##### `crossmool_sm4_decrypt_gcm_hex` ⭐ 推荐

SM4 GCM 解密（从 HEX 字符串）。

| 字段 | 描述 |
|------|------|
| **签名** | `int crossmool_sm4_decrypt_gcm_hex(const unsigned char* key, const char* ciphertext_hex, unsigned char** plaintext, size_t* plaintext_len)` |
| **入参** | `key` — 密钥（16 字节） |
| | `ciphertext_hex` — HEX(IV+密文+Tag) |
| **出参** | `plaintext` — 明文, `plaintext_len` — 明文长度 |
| **注意** | 调用者需调用 `free()` 释放 `plaintext` |

##### `crossmool_sm4_decrypt_gcm_base64`

SM4 GCM 解密（从 Base64 字符串）。

**调用示例**：

```c
#include "crossmool_sm4.h"

unsigned char key[16];
crossmool_sm4_generate_key(key);

unsigned char plaintext[] = "Hello, SM4!";
char* ciphertext_hex = NULL;
crossmool_sm4_encrypt_gcm_hex(key, plaintext, strlen((char*)plaintext), &ciphertext_hex);
printf("Ciphertext: %s\n", ciphertext_hex);

unsigned char* decrypted = NULL;
size_t decrypted_len = 0;
crossmool_sm4_decrypt_gcm_hex(key, ciphertext_hex, &decrypted, &decrypted_len);
printf("Decrypted: %.*s\n", (int)decrypted_len, decrypted);

free(ciphertext_hex);
free(decrypted);
```

---

### 3.4 C — 工具函数

##### `crossmool_error_string`

获取错误描述。

| 字段 | 描述 |
|------|------|
| **签名** | `const char* crossmool_error_string(int error_code)` |
| **入参** | `error_code` — 错误码 |
| **出参** | 错误描述字符串（静态，无需释放） |

##### `crossmool_version`

获取库版本号。

| 字段 | 描述 |
|------|------|
| **签名** | `const char* crossmool_version(void)` |
| **出参** | 版本号字符串（格式：`major.minor.patch`） |

##### `crossmool_is_hex_string` / `crossmool_is_base64_string`

判断字符串是否为 HEX / Base64 格式。

##### `crossmool_hex_encode` / `crossmool_hex_decode`

HEX 编解码。

##### `crossmool_base64_encode` / `crossmool_base64_decode`

Base64 编解码。

##### `crossmool_string_to_bytes` / `crossmool_bytes_to_string`

字符串与字节数组转换（支持字符集）。

##### `crossmool_cleanup`

清理全局资源。

---

## 4. C++ 语言接口

**头文件位置**: `cpp/crossmool/include/`  
**命名空间**: 全局（无命名空间）  
**底层库**: GmSSL（C++ 封装）

### 4.1 C++ — SM2Util

**类**: `SM2Util`（所有方法为 `static`）

**内部结构体**：

```cpp
struct KeyPair {
    std::string publicKey;
    std::string privateKey;
};

struct CiphertextSignaturePair {
    std::string ciphertext;
    std::string signature;
};
```

#### 4.1.1 密钥生成

##### `generateKeyPairBase64`

| 字段 | 描述 |
|------|------|
| **签名** | `static KeyPair generateKeyPairBase64()` |
| **入参** | 无 |
| **出参** | `KeyPair` — Base64 编码的公私钥对 |

##### `generateKeyPairHex`

| 字段 | 描述 |
|------|------|
| **签名** | `static KeyPair generateKeyPairHex()` |
| **出参** | `KeyPair` — HEX 编码的公私钥对（公钥 130 字符 hex，私钥 64 字符 hex） |

##### `generateKeyPairRaw`

| 字段 | 描述 |
|------|------|
| **签名** | `static KeyPair generateKeyPairRaw()` |
| **入参** | 无 |
| **出参** | `KeyPair` — X.509/PKCS#8 DER 的 HEX 编码公私钥对 |
| **说明** | 公钥为 X.509 SubjectPublicKeyInfo DER 的 HEX 编码，私钥为 PKCS#8 PrivateKeyInfo DER 的 HEX 编码。与 Go `GenerateKeyPair()` / Rust `generate_keypair()` 输出格式兼容。 |

**调用示例**：

```cpp
#include "SM2Util.h"

auto keypair = SM2Util::generateKeyPairHex();
std::cout << "Public: " << keypair.publicKey << std::endl;
std::cout << "Private: " << keypair.privateKey << std::endl;

// 或生成 DER 原始格式
auto rawKeypair = SM2Util::generateKeyPairRaw();
```

---

#### 4.1.2 加密 / 解密

##### `encrypt` / `encryptToBytes` / `encryptToHex` / `encryptToBase64`

| 方法 | 签名 | 入参 | 出参 |
|------|------|------|------|
| `encryptToBytes` | `static std::vector<unsigned char> encryptToBytes(const std::vector<unsigned char>& content, const std::vector<unsigned char>& publicKey)` | `content` — 明文字节, `publicKey` — 公钥字节 | 密文字节 |
| `encryptToBytes` | `static std::vector<unsigned char> encryptToBytes(const std::string& content, const std::string& publicKey, const std::string& charset = "UTF-8")` | `content` — 明文字符串, `publicKey` — 公钥字符串 | 密文字节 |
| `encryptToHex` | `static std::string encryptToHex(const std::string& content, const std::string& publicKey)` | 同上 | HEX 密文 |
| `encryptToBase64` | `static std::string encryptToBase64(const std::string& content, const std::string& publicKey)` | 同上 | Base64 密文 |
| `encrypt` | `static std::string encrypt(const std::string& content, const std::string& publicKey, bool toBase64 = false)` | `toBase64` — false=HEX, true=Base64 | HEX 或 Base64 密文 |

##### `decrypt` / `decryptToBytes` / `decryptToCharset`

| 方法 | 签名 | 入参 | 出参 |
|------|------|------|------|
| `decryptToBytes` | `static std::vector<unsigned char> decryptToBytes(const std::vector<unsigned char>& content, const std::vector<unsigned char>& privateKey)` | 密文字节 + 私钥字节 | 明文字节 |
| `decryptToBytes` | `static std::vector<unsigned char> decryptToBytes(const std::string& content, const std::string& privateKey)` | 密文字符串 + 私钥字符串 | 明文字节 |
| `decryptToCharset` | `static std::string decryptToCharset(const std::string& content, const std::string& privateKey, const std::string& charset = "UTF-8")` | 同上 + `charset` | 明文字符串 |
| `decrypt` | `static std::string decrypt(const std::string& content, const std::string& privateKey)` | 密文字符串 + 私钥字符串 | UTF-8 明文 |

**调用示例**：

```cpp
auto keypair = SM2Util::generateKeyPairHex();

// 加密
std::string ciphertext = SM2Util::encrypt("Hello, SM2!", keypair.publicKey);
std::cout << "Encrypted: " << ciphertext << std::endl;

// 解密
std::string plaintext = SM2Util::decrypt(ciphertext, keypair.privateKey);
std::cout << "Decrypted: " << plaintext << std::endl;
```

---

#### 4.1.3 签名 / 验签

| 方法 | 签名 | 出参 |
|------|------|------|
| `sign` | `static std::vector<unsigned char> sign(const std::vector<unsigned char>& content, const std::vector<unsigned char>& privateKey)` | 签名字节 |
| `sign` | `static std::vector<unsigned char> sign(const std::string& content, const std::string& privateKey, const std::string& charset = "UTF-8")` | 签名字节 |
| `signToHex` | `static std::string signToHex(const std::string& content, const std::string& privateKey)` | HEX 签名 |
| `signToBase64` | `static std::string signToBase64(const std::string& content, const std::string& privateKey)` | Base64 签名 |
| `sign` | `static std::string sign(const std::string& content, const std::string& privateKey, bool toBase64 = false)` | HEX 或 Base64 签名 |
| `verify` | `static bool verify(const std::vector<unsigned char>& content, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& publicKey)` | 验证结果 |
| `verify` | `static bool verify(const std::string& content, const std::string& publicKey, const std::string& signature, const std::string& charset = "UTF-8")` | 验证结果 |

#### 4.1.4 加密签名组合

| 方法 | 签名 |
|------|------|
| `encryptSign` | `static CiphertextSignaturePair encryptSign(const std::string& content, const std::string& encPublicKey, const std::string& signPrivateKey, bool toBase64 = false)` |
| `verifyDecrypt` | `static std::string verifyDecrypt(const std::string& content, const std::string& signature, const std::string& signPublicKey, const std::string& decPrivateKey)` |

---

### 4.2 C++ — SM3Util

**类**: `SM3Util`（所有方法为 `static`）

#### 杂凑

| 方法 | 签名 | 入参 | 出参 |
|------|------|------|------|
| `digest` | `static std::vector<unsigned char> digest(const std::vector<unsigned char>& input)` | `input` — 输入字节 | 杂凑字节 |
| `digestToHex` | `static std::string digestToHex(const std::vector<unsigned char>& input)` | `input` — 输入字节 | HEX 杂凑值 |
| `digestToStr` | `static std::string digestToStr(const std::vector<unsigned char>& input, bool toBase64 = false)` | `toBase64` — false=HEX, true=Base64 | HEX/Base64 杂凑值 |
| `digestToStr` | `static std::string digestToStr(const std::string& input, const std::string& charset = "UTF-8", bool toBase64 = false)` | 字符串输入 + 字符集 | HEX/Base64 杂凑值 |
| `digestToStr` | `static std::string digestToStr(const std::string& input)` | 字符串输入（UTF-8） | HEX 杂凑值（默认） |

#### HMAC-SM3

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateHmacKey` | `static std::vector<unsigned char> generateHmacKey(int keyLengthInBytes = 32)` | 随机 HMAC 密钥 |
| `generateHmacKeyToStr` | `static std::string generateHmacKeyToStr(int keyLengthInBytes = 32, bool toBase64 = false)` | HEX/Base64 密钥 |
| `hmac` | `static std::vector<unsigned char> hmac(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data)` | HMAC 字节 |
| `hmac` | `static std::vector<unsigned char> hmac(const std::string& key, const std::string& data)` | HMAC 字节 |
| `hmacToStr` | `static std::string hmacToStr(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data, bool toBase64 = false)` | HEX/Base64 HMAC |
| `hmacToStr` | `static std::string hmacToStr(const std::string& key, const std::string& data, bool toBase64 = false)` | HEX/Base64 HMAC |
| `hmacVerify` | `static bool hmacVerify(const std::string& key, const std::string& data, const std::string& receivedHmac)` | 验证结果 |

**调用示例**：

```cpp
#include "SM3Util.h"

std::string hash = SM3Util::digestToStr("Hello, SM3!");
std::cout << "SM3: " << hash << std::endl;

auto key = SM3Util::generateHmacKey();
auto mac = SM3Util::hmacToStr(key, std::vector<unsigned char>(data, data+len));
```

---

### 4.3 C++ — SM4Util

**类**: `SM4Util`（所有方法为 `static`）

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateKey` | `static std::vector<unsigned char> generateKey()` | 16 字节随机密钥 |
| `generateKeyAsHex` | `static std::string generateKeyAsHex()` | HEX 密钥 |
| `parseHexKey` | `static std::vector<unsigned char> parseHexKey(const std::string& hexKey)` | 解析后的密钥字节 |
| `encryptGcm` | `static std::string encryptGcm(const std::vector<unsigned char>& key, const std::vector<unsigned char>& input, bool toBase64 = false)` | HEX/Base64 密文 |
| `decryptGcm` | `static std::vector<unsigned char> decryptGcm(const std::vector<unsigned char>& key, const std::string& ciphertextEncoded)` | 明文字节（自动检测 HEX/Base64） |
| `encryptGcmString` | `static std::string encryptGcmString(const std::vector<unsigned char>& key, const std::string& plainText)` | Base64 密文 |
| `decryptGcmToString` | `static std::string decryptGcmToString(const std::vector<unsigned char>& key, const std::string& ciphertextBase64)` | UTF-8 明文 |

**调用示例**：

```cpp
#include "SM4Util.h"

auto key = SM4Util::generateKey();
std::string encrypted = SM4Util::encryptGcm(key, std::vector<unsigned char>(plaintext, plaintext+len));
auto decrypted = SM4Util::decryptGcm(key, encrypted);
```

---

### 4.4 C++ — 工具类

#### Base64Util

| 方法 | 签名 |
|------|------|
| `encodeBase64Str` | `static std::string encodeBase64Str(const std::vector<unsigned char>& bytes)` |
| `decodeBase64Str` | `static std::vector<unsigned char> decodeBase64Str(const std::string& base64)` |
| `isBase64String` | `static bool isBase64String(const std::string& str)` |

#### HexUtil

| 方法 | 签名 |
|------|------|
| `encodeHexStr` | `static std::string encodeHexStr(const std::vector<unsigned char>& bytes)` |
| `decodeHexStr` | `static std::vector<unsigned char> decodeHexStr(const std::string& hex)` |
| `isHexString` | `static bool isHexString(const std::string& str)` |

#### StringUtil

| 方法 | 签名 |
|------|------|
| `stringToBytes` | `static std::vector<unsigned char> stringToBytes(const std::string& str, const std::string& charset = "UTF-8")` |
| `bytesToString` | `static std::string bytesToString(const std::vector<unsigned char>& bytes, const std::string& charset = "UTF-8")` |
| `isHexString` | `static bool isHexString(const std::string& str)` |
| `isBase64String` | `static bool isBase64String(const std::string& str)` |

---

## 5. C# 语言接口

**命名空间**: `Crossmool.Crypto`  
**底层库**: BouncyCastle (Org.BouncyCastle)

### 5.1 C# — SM2Util

**类**: `public static class SM2Util`

#### 5.1.1 密钥生成

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateKeyPair` | `public static string generateKeyPair()` | JSON 格式密钥（`{"privateKeyHex":"...","publicKeyHex":"..."}`） |
| `exportPrivateKeyPem` | `public static string exportPrivateKeyPem(byte[] privateKeyBytes)` | PEM 格式私钥 |
| `exportPublicKeyPem` | `public static string exportPublicKeyPem(byte[] publicKeyBytes)` | PEM 格式公钥 |
| `importPrivateKeyPem` | `public static byte[] importPrivateKeyPem(string pem)` | 私钥字节 |
| `importPublicKeyPem` | `public static byte[] importPublicKeyPem(string pem)` | 公钥字节 |

#### 5.1.2 加密 / 解密

| 方法 | 签名 | 出参 |
|------|------|------|
| `encrypt` | `public static byte[] encrypt(byte[] originalTextBytes, byte[] publicKeyBytes)` | 密文字节 |
| `encrypt` | `public static string encrypt(string originalText, string publicKeyString, bool toBase64 = false)` | HEX/Base64 密文 |
| `encryptToHex` | `public static string encryptToHex(string originalText, string publicKeyString)` | HEX 密文 |
| `encryptToBase64` | `public static string encryptToBase64(string originalText, string publicKeyString)` | Base64 密文 |
| `decrypt` | `public static byte[] decrypt(byte[] encryptedTextBytes, byte[] privateKeyBytes)` | 明文字节 |
| `decrypt` | `public static string decrypt(string encryptedText, string privateKeyString)` | UTF-8 明文 |
| `decryptFromHex` | `public static string decryptFromHex(string encryptedTextHex, string privateKeyString)` | UTF-8 明文 |

#### 5.1.3 签名 / 验签

| 方法 | 签名 | 出参 |
|------|------|------|
| `sign` | `public static byte[] sign(byte[] messageBytes, byte[] privateKeyBytes)` | 签名字节 |
| `sign` | `public static string sign(string message, string privateKeyString, bool toBase64 = false)` | HEX/Base64 签名 |
| `signToHex` | `public static string signToHex(string message, string privateKeyString)` | HEX 签名 |
| `signToBase64` | `public static string signToBase64(string message, string privateKeyString)` | Base64 签名 |
| `verify` | `public static bool verify(byte[] messageBytes, byte[] signatureBytes, byte[] publicKeyBytes)` | 验证结果 |
| `verify` | `public static bool verify(string message, string signatureString, string publicKeyString)` | 验证结果 |

#### 5.1.4 加密签名组合

| 方法 | 签名 |
|------|------|
| `encryptSign` | `public static (byte[] ciphertext, byte[] signature) encryptSign(byte[] messageBytes, byte[] publicKeyBytes, byte[] privateKeyBytes)` |
| `encryptSign` | `public static (string ciphertext, string signature) encryptSign(string message, string publicKeyString, string privateKeyString, bool toBase64 = false)` |
| `verifyDecrypt` | `public static string verifyDecrypt(string ciphertextString, string signatureString, string signPublicKeyString, string decPrivateKeyString)` |

**调用示例**：

```csharp
using Crossmool.Crypto;

string jsonKeyPair = SM2Util.generateKeyPair();
// {"privateKeyHex":"...", "publicKeyHex":"..."}

string encrypted = SM2Util.encrypt("Hello, SM2!", publicKeyHex);
string decrypted = SM2Util.decrypt(encrypted, privateKeyHex);
Console.WriteLine(decrypted);

string signature = SM2Util.sign("Hello", privateKeyHex);
bool valid = SM2Util.verify("Hello", signature, publicKeyHex);
```

---

### 5.2 C# — SM3Util

**类**: `public static class SM3Util`

#### 杂凑

| 方法 | 签名 | 出参 |
|------|------|------|
| `digest` | `public static byte[] digest(byte[] input)` | 杂凑字节 |
| `digestToStr` | `public static string digestToStr(byte[] input, bool toBase64 = false)` | HEX/Base64 杂凑 |
| `digest` | `public static string digest(string input, bool toBase64 = false)` | HEX/Base64 杂凑 |
| `digestBase64` | `public static string digestBase64(string input)` | Base64 杂凑 |

#### HMAC-SM3

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateHmacKey` | `public static byte[] generateHmacKey(int keyLengthInBytes = 32)` | 随机 HMAC 密钥 |
| `generateHmacKeyToStr` | `public static string generateHmacKeyToStr(int keyLengthInBytes = 32, bool toBase64 = false)` | HEX/Base64 密钥 |
| `hmac` | `public static byte[] hmac(byte[] key, byte[] data)` | HMAC 字节 |
| `hmac` | `public static byte[] hmac(string key, string data)` | HMAC 字节 |
| `hmacToStr` | `public static string hmacToStr(byte[] key, byte[] data, bool toBase64 = false)` | HEX/Base64 HMAC |
| `hmacToStr` | `public static string hmacToStr(string key, string data, bool toBase64 = false)` | HEX/Base64 HMAC |

---

### 5.3 C# — SM4Util

**类**: `public static class SM4Util`

| 方法 | 签名 | 出参 |
|------|------|------|
| `GenerateKey` | `public static byte[] GenerateKey()` | 16 字节随机密钥 |
| `GenerateKeyAsHex` | `public static string GenerateKeyAsHex()` | HEX 密钥 |
| `ParseHexKey` | `public static byte[] ParseHexKey(string hexKey)` | 解析后的密钥 |
| `EncryptGcm` | `public static string EncryptGcm(byte[] key, byte[] plaintext, bool toBase64 = false)` | HEX/Base64(IV+密文+Tag) |
| `EncryptGcmWithIV` | `public static string EncryptGcmWithIV(byte[] key, byte[] plaintext, byte[] iv, bool toBase64 = false)` | HEX/Base64(IV+密文+Tag) |
| `EncryptGcmHex` | `public static string EncryptGcmHex(byte[] key, byte[] plaintext)` | HEX(IV+密文+Tag) |
| `DecryptGcm` | `public static byte[] DecryptGcm(byte[] key, string ciphertextEncoded)` | 明文字节（自动检测） |
| `DecryptGcmFromHex` | `public static byte[] DecryptGcmFromHex(byte[] key, string ciphertextHex)` | 明文字节 |
| `EncryptGcmString` | `public static string EncryptGcmString(byte[] key, string plainText, bool toBase64 = false)` | HEX/Base64 密文 |
| `DecryptGcmToString` | `public static string DecryptGcmToString(byte[] key, string ciphertextEncoded)` | UTF-8 明文 |

**调用示例**：

```csharp
byte[] key = SM4Util.GenerateKey();
string encrypted = SM4Util.EncryptGcm(key, Encoding.UTF8.GetBytes("Hello, SM4!"));
byte[] decrypted = SM4Util.DecryptGcm(key, encrypted);
Console.WriteLine(Encoding.UTF8.GetString(decrypted));
```

---

### 5.4 EncodingUtils

**类**: `public static class EncodingUtils`（位于 `Crossmool.Crypto.Utils` 命名空间）

| 方法 | 签名 |
|------|------|
| `Utf8GetBytes` | `public static byte[] Utf8GetBytes(string s)` |
| `Utf8GetString` | `public static string Utf8GetString(byte[] bytes)` |
| `ToBase64` | `public static string ToBase64(byte[] bytes)` |
| `FromBase64` | `public static byte[] FromBase64(string base64)` |
| `ToHex` | `public static string ToHex(byte[] bytes)` |
| `FromHex` | `public static byte[] FromHex(string hex)` |
| `LooksLikeHex` | `public static bool LooksLikeHex(string s)` |
| `ParseBase64OrHex` | `public static byte[] ParseBase64OrHex(string s)` |

---

## 6. Java 语言接口

**包名**: `cc.iili.tools.crossmool`  
**底层库**: BouncyCastle (org.bouncycastle)

### 6.1 Java — SM2Util

**类**: `public class SM2Util`（静态方法类）

**数据类**：

```java
// cc.iili.tools.crossmool.bean.SerialKeyPair
public class SerialKeyPair {
    private String publicKey;
    private String privateKey;
    // + getters/setters/constructors
}

// cc.iili.tools.crossmool.bean.CiphertextSignaturePair
public class CiphertextSignaturePair {
    private String ciphertext;
    private String signature;
    // + getters/setters/constructors
}
```

#### 6.1.1 密钥生成

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateKeyPair` | `public static KeyPair generateKeyPair()` | `java.security.KeyPair` (JCA) |
| `generateKeyPairBase64` | `public static SerialKeyPair generateKeyPairBase64()` | Base64 编码密钥对 |
| `generateKeyPairHex` | `public static SerialKeyPair generateKeyPairHex()` | HEX 编码密钥对 |

#### 6.1.2 加密 / 解密

| 方法 | 签名 | 入参 | 出参 |
|------|------|------|------|
| `encryptToBytes` | `public static byte[] encryptToBytes(byte[] content, byte[] publicKey)` | 明文字节 + 公钥字节 | 密文字节 |
| `encryptToBytes` | `public static byte[] encryptToBytes(String content, String publicKey, Charset charset)` | 明文字符串 + 公钥 + 字符集 | 密文字节 |
| `encryptToBytes` | `public static byte[] encryptToBytes(String content, String publicKey)` | 明文字符串 + 公钥（UTF-8） | 密文字节 |
| `encryptToHex` | `public static String encryptToHex(String content, String publicKey)` | 同上 | HEX 密文 |
| `encryptToBase64` | `public static String encryptToBase64(String content, String publicKey)` | 同上 | Base64 密文 |
| `encrypt` | `public static String encrypt(String content, String publicKey, boolean toBase64)` | `toBase64` — false=HEX, true=Base64 | HEX/Base64 密文 |
| **`encrypt` ⭐** | `public static String encrypt(String content, String publicKey)` | 同上（默认 HEX） | HEX 密文 |
| `decryptToBytes` | `public static byte[] decryptToBytes(byte[] content, byte[] privateKey)` | 密文字节 + 私钥字节 | 明文字节 |
| `decryptToBytes` | `public static byte[] decryptToBytes(String content, String privateKey)` | 密文字符串（HEX/Base64）+ 私钥 | 明文字节 |
| `decryptToCharset` | `public static String decryptToCharset(String content, String privateKey, Charset charset)` | 同上 + 字符集 | 明文字符串 |
| **`decrypt` ⭐** | `public static String decrypt(String content, String privateKey)` | 同上（UTF-8 输出） | 明文字符串 |

#### 6.1.3 签名 / 验签

| 方法 | 签名 | 出参 |
|------|------|------|
| `sign` | `public static byte[] sign(byte[] content, byte[] privateKey)` | 签名字节 |
| `sign` | `public static byte[] sign(String content, String privateKey, Charset charset)` | 签名字节 |
| `signToHex` | `public static String signToHex(String content, String privateKey)` | HEX 签名 |
| `signToBase64` | `public static String signToBase64(String content, String privateKey)` | Base64 签名 |
| `sign` | `public static String sign(String content, String privateKey, boolean toBase64)` | HEX/Base64 签名 |
| **`sign` ⭐** | `public static String sign(String content, String privateKey)` | HEX 签名（默认） |
| `verify` | `public static boolean verify(byte[] content, byte[] signature, byte[] publicKeyBytes)` | 验证结果 |
| `verify` | `public static boolean verify(String content, String publicKey, String signature, Charset charset)` | 验证结果 |
| **`verify` ⭐** | `public static boolean verify(String content, String publicKey, String signature)` | 验证结果（UTF-8） |

#### 6.1.4 加密签名组合

| 方法 | 签名 |
|------|------|
| `encryptSign` | `public static CiphertextSignaturePair encryptSign(String content, String encPublicKey, String signPrivateKey, boolean toBase64)` |
| **`encryptSign` ⭐** | `public static CiphertextSignaturePair encryptSign(String content, String encPublicKey, String signPrivateKey)` |
| `encryptSignWithHexKeys` | `public static CiphertextSignaturePair encryptSignWithHexKeys(String content, String encPublicKey, String signPrivateKey)` |
| `encryptSignWithBase64Keys` | `public static CiphertextSignaturePair encryptSignWithBase64Keys(String content, String encPublicKey, String signPrivateKey)` |
| `encryptSignWithSameFormatKeys` | `public static CiphertextSignaturePair encryptSignWithSameFormatKeys(String content, String encPublicKey, String signPrivateKey)` |
| **`verifyDecrypt` ⭐** | `public static String verifyDecrypt(String content, String signature, String signPublicKey, String decPrivateKey)` |
| `verifyDecrypt` | `public static String verifyDecrypt(CiphertextSignaturePair cipherSigPair, String signPublicKey, String decPrivateKey)` |

**调用示例**：

```java
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

// 生成密钥对
SerialKeyPair keypair = SM2Util.generateKeyPairHex();
System.out.println("Public: " + keypair.getPublicKey());
System.out.println("Private: " + keypair.getPrivateKey());

// 加密/解密
String encrypted = SM2Util.encrypt("Hello, SM2!", keypair.getPublicKey());
String decrypted = SM2Util.decrypt(encrypted, keypair.getPrivateKey());
System.out.println(decrypted);  // Hello, SM2!

// 签名/验签
String signature = SM2Util.sign("Hello", keypair.getPrivateKey());
boolean valid = SM2Util.verify("Hello", keypair.getPublicKey(), signature);

// 加密签名组合
CiphertextSignaturePair pair = SM2Util.encryptSign("Hello", publicKey, privateKey);
String plain = SM2Util.verifyDecrypt(pair.getCiphertext(), pair.getSignature(), pubKey, privKey);
```

---

### 6.2 Java — SM3Util

**类**: `public class SM3Util`

#### 杂凑

| 方法 | 签名 | 出参 |
|------|------|------|
| `digest` | `public static byte[] digest(byte[] input)` | 杂凑字节 |
| `digestToHex` | `public static String digestToHex(byte[] input)` | HEX 杂凑 |
| `digestToStr` | `public static String digestToStr(byte[] input, boolean toBase64)` | HEX/Base64 杂凑 |
| `digestToStr` | `public static String digestToStr(byte[] input)` | HEX 杂凑（默认） |
| `digestToStr` | `public static String digestToStr(String input, Charset charset, boolean toBase64)` | HEX/Base64 杂凑 |
| **`digestToStr` ⭐** | `public static String digestToStr(String input, boolean toBase64)` | HEX/Base64 杂凑（UTF-8） |
| **`digestToStr` ⭐** | `public static String digestToStr(String input)` | HEX 杂凑（默认, UTF-8） |

> 同时提供 `messageDigest*` 系列方法使用 JCA API。

#### HMAC-SM3

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateHmacKey` | `public static byte[] generateHmacKey(int keyLengthInBytes)` | 随机密钥（≥32字节） |
| `generateHmacKey` | `public static byte[] generateHmacKey()` | 32 字节密钥（默认） |
| `generateHmacKeyToStr` | `public static String generateHmacKeyToStr(int keyLengthInBytes, boolean toBase64)` | HEX/Base64 密钥 |
| `generateHmacKeyToStr` | `public static String generateHmacKeyToStr(boolean toBase64)` | 32 字节 HEX/Base64 密钥 |
| `hmac` | `public static byte[] hmac(byte[] key, byte[] data)` | HMAC 字节 |
| `hmac` | `public static byte[] hmac(String key, String data)` | HMAC 字节 |
| `hmacToStr` | `public static String hmacToStr(byte[] key, byte[] data, boolean toBase64)` | HEX/Base64 HMAC |
| **`hmacToStr` ⭐** | `public static String hmacToStr(byte[] key, byte[] data)` | HEX HMAC（默认） |
| `hmacToStr` | `public static String hmacToStr(String key, String data, boolean toBase64)` | HEX/Base64 HMAC |
| **`hmacToStr` ⭐** | `public static String hmacToStr(String key, String data)` | HEX HMAC（默认） |
| `hmacVerify` | `public static boolean hmacVerify(String key, String data, String receivedHmac)` | 验证结果 |

**调用示例**：

```java
import cc.iili.tools.crossmool.tool.SM3Util;

String hash = SM3Util.digestToStr("Hello, SM3!");
System.out.println(hash);  // HEX 杂凑值

byte[] hmacKey = SM3Util.generateHmacKey();
String mac = SM3Util.hmacToStr(hmacKey, someData);
```

---

### 6.3 Java — SM4Util

**类**: `public class SM4Util`

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateKey` | `public static byte[] generateKey()` | 16 字节随机密钥 |
| `generateKeyAsHex` | `public static String generateKeyAsHex()` | HEX 密钥 |
| `generateKeyAsBase64` | `public static String generateKeyAsBase64()` | Base64 密钥 |
| `parseHexKey` | `public static byte[] parseHexKey(String hexKey)` | 解析后的密钥 |
| `parseBase64Key` | `public static byte[] parseBase64Key(String base64Key)` | 解析后的密钥 |
| `parseKey` | `public static byte[] parseKey(String key)` | 自动检测 HEX/Base64 |
| `generateGcmIv` | `public static byte[] generateGcmIv()` | 12 字节随机 IV |
| `encryptGcmNative` | `public static String encryptGcmNative(byte[] key, byte[] input)` | Base64(IV+密文) |
| `encryptGcmNative` | `public static String encryptGcmNative(byte[] key, byte[] input, byte[] iv)` | Base64(IV+密文) |
| `decryptGcmNative` | `public static byte[] decryptGcmNative(byte[] key, String encodedData)` | 明文字节 |
| `decryptGcmNativeToString` | `public static String decryptGcmNativeToString(byte[] key, String encodedData)` | UTF-8 明文 |
| `encryptGcmJca` | `public static String encryptGcmJca(byte[] key, String plainText)` | Base64(IV+密文) |
| `encryptGcmJca` | `public static String encryptGcmJca(byte[] key, String plainText, byte[] iv)` | Base64(IV+密文) |
| `decryptGcmJca` | `public static String decryptGcmJca(byte[] key, String encodedData)` | UTF-8 明文 |
| **`encrypt` ⭐** | `public static String encrypt(byte[] key, byte[] plaintext, boolean toBase64)` | HEX/Base64 密文 |
| **`encrypt` ⭐** | `public static String encrypt(byte[] key, byte[] plaintext)` | HEX 密文 |
| **`encrypt` ⭐** | `public static String encrypt(String key, String plaintext, boolean toBase64)` | HEX/Base64 密文 |
| **`encrypt` ⭐** | `public static String encrypt(String key, String plaintext)` | HEX 密文 |
| **`decrypt` ⭐** | `public static String decrypt(byte[] key, String ciphertext)` | UTF-8 明文 |
| **`decrypt` ⭐** | `public static String decrypt(String key, String ciphertext)` | UTF-8 明文 |

**调用示例**：

```java
import cc.iili.tools.crossmool.tool.SM4Util;

String hexKey = SM4Util.generateKeyAsHex();
String encrypted = SM4Util.encrypt(hexKey, "Hello, SM4!");
System.out.println(encrypted);
String decrypted = SM4Util.decrypt(hexKey, encrypted);
System.out.println(decrypted);  // Hello, SM4!
```

---

### 6.4 Java — 工具类

#### HexUtil

| 方法 | 签名 |
|------|------|
| `isHexString` | `public static boolean isHexString(String str)` |
| `encodeHexStr` | `public static String encodeHexStr(byte[] data)` |
| `decodeHexStr` | `public static byte[] decodeHexStr(String hex)` |

#### Base64Util

| 方法 | 签名 |
|------|------|
| `isBase64String` | `public static boolean isBase64String(String str)` |
| `encodeBase64Str` | `public static String encodeBase64Str(byte[] data)` |
| `decodeBase64Str` | `public static byte[] decodeBase64Str(String base64)` |

---

## 7. Python 语言接口

**包名**: `crossmool`  
**导入方式**: `from crossmool import ...`  
**底层库**: gmssl

### 7.1 Python — SM2Util

**类**: `SM2Util`（所有方法为 `@staticmethod`）

#### 7.1.1 密钥生成

| 方法 | 签名 | 出参 |
|------|------|------|
| `generate_keypair_raw` | `@staticmethod generate_keypair_raw() -> (str, str)` | `(private_hex, public_hex)` |

#### 7.1.2 加密 / 解密

| 方法 | 签名 | 入参 | 出参 |
|------|------|------|------|
| `encrypt_to_hex` | `@staticmethod encrypt_to_hex(content: bytes, public_key) -> str` | `content` — 明文字节, `public_key` — 公钥（HEX/Base64/bytes） | HEX 密文 |
| `encrypt_to_base64` | `@staticmethod encrypt_to_base64(content: bytes, public_key) -> str` | 同上 | Base64 密文 |
| `decrypt_from_hex` | `@staticmethod decrypt_from_hex(cipher_hex: str, private_key, public_key=None) -> bytes` | `cipher_hex` — HEX 密文, `private_key` — 私钥 | 明文字节 |
| `decrypt_from_base64` | `@staticmethod decrypt_from_base64(cipher_b64: str, private_key) -> bytes` | Base64 密文 + 私钥 | 明文字节 |
| **`encrypt` ⭐** | `@staticmethod encrypt(content: str, public_key, to_base64: bool = False) -> str` | `content` — UTF-8 字符串 | HEX/Base64 密文 |
| **`decrypt` ⭐** | `@staticmethod decrypt(cipher_text: str, private_key) -> str` | 自动检测 HEX/Base64 | UTF-8 明文 |

#### 7.1.3 签名 / 验签

| 方法 | 签名 | 出参 |
|------|------|------|
| `sign_to_der` | `@staticmethod sign_to_der(content: bytes, private_key) -> bytes` | DER 签名字节 |
| `sign_to_hex` | `@staticmethod sign_to_hex(content: bytes, private_key) -> str` | HEX 签名 |
| `sign_to_base64` | `@staticmethod sign_to_base64(content: bytes, private_key) -> str` | Base64 签名 |
| `verify` | `@staticmethod verify(content: bytes, public_key, signature) -> bool` | 验证结果 |
| **`sign` ⭐** | `@staticmethod sign(content: str, private_key, to_base64: bool = False) -> str` | HEX/Base64 签名 |
| **`verify_str` ⭐** | `@staticmethod verify_str(content: str, public_key, signature: str) -> bool` | 验证结果 |

**调用示例**：

```python
from crossmool import SM2Util

# 生成密钥对
priv_hex, pub_hex = SM2Util.generate_keypair_raw()

# 加密/解密
encrypted = SM2Util.encrypt("Hello, SM2!", pub_hex)
decrypted = SM2Util.decrypt(encrypted, priv_hex)
print(decrypted)  # Hello, SM2!

# 签名/验签
sig = SM2Util.sign("Hello", priv_hex)
valid = SM2Util.verify_str("Hello", pub_hex, sig)
print(valid)  # True
```

---

### 7.2 Python — SM3Util

**类**: `SM3Util`

#### 杂凑

| 方法 | 签名 | 出参 |
|------|------|------|
| `digest` | `@staticmethod digest(data: bytes) -> bytes` | 杂凑字节 |
| `digest_to_hex` | `@staticmethod digest_to_hex(data: bytes) -> str` | HEX 杂凑 |
| `digest_to_base64` | `@staticmethod digest_to_base64(data: bytes) -> str` | Base64 杂凑 |
| `digest_to_str` | `@staticmethod digest_to_str(data: bytes, to_base64: bool = False) -> str` | HEX/Base64 杂凑 |
| **`digest_str` ⭐** | `@staticmethod digest_str(input_str: str, to_base64: bool = False) -> str` | HEX/Base64 杂凑 |

#### HMAC-SM3

| 方法 | 签名 | 出参 |
|------|------|------|
| `generate_hmac_key` | `@staticmethod generate_hmac_key(key_length: int = 32) -> bytes` | 随机密钥 |
| `generate_hmac_key_to_str` | `@staticmethod generate_hmac_key_to_str(key_length: int = 32, to_base64: bool = False) -> str` | HEX/Base64 密钥 |
| `hmac` | `@staticmethod hmac(key: bytes, data: bytes) -> bytes` | HMAC 字节 |
| `hmac_from_str` | `@staticmethod hmac_from_str(key_str: str, data_str: str) -> bytes` | HMAC 字节 |
| `hmac_to_hex` | `@staticmethod hmac_to_hex(key: bytes, data: bytes) -> str` | HEX HMAC |
| `hmac_to_base64` | `@staticmethod hmac_to_base64(key: bytes, data: bytes) -> str` | Base64 HMAC |
| `hmac_to_str` | `@staticmethod hmac_to_str(key: bytes, data: bytes, to_base64: bool = False) -> str` | HEX/Base64 HMAC |
| **`hmac_str` ⭐** | `@staticmethod hmac_str(key_str: str, data_str: str, to_base64: bool = False) -> str` | HEX/Base64 HMAC |

**调用示例**：

```python
from crossmool import SM3Util

hash_hex = SM3Util.digest_str("Hello, SM3!")
print(hash_hex)

key = SM3Util.generate_hmac_key()
mac = SM3Util.hmac_to_hex(key, b"data")
```

---

### 7.3 Python — SM4Util

**类**: `SM4Util`

| 方法 | 签名 | 出参 |
|------|------|------|
| `generate_key` | `@staticmethod generate_key() -> bytes` | 16 字节随机密钥 |
| `generate_key_hex` | `@staticmethod generate_key_hex() -> str` | HEX 密钥 |
| `parse_hex_key` | `@staticmethod parse_hex_key(hex_key: str) -> bytes` | 解析后的密钥 |
| `encrypt_gcm` | `@staticmethod encrypt_gcm(key: bytes, plaintext: bytes, aad: bytes = b'', to_base64: bool = False) -> str` | HEX/Base64 密文 |
| `encrypt_gcm_hex` | `@staticmethod encrypt_gcm_hex(key: bytes, plaintext: bytes, aad: bytes = b'') -> str` | HEX 密文 |
| `decrypt_gcm` | `@staticmethod decrypt_gcm(key: bytes, ciphertext_str: str, aad: bytes = b'') -> bytes` | 明文字节（自动检测） |
| `decrypt_gcm_from_hex` | `@staticmethod decrypt_gcm_from_hex(key: bytes, hex_str: str, aad: bytes = b'') -> bytes` | 明文字节 |
| **`encrypt_gcm_string` ⭐** | `@staticmethod encrypt_gcm_string(key: bytes, plain_text: str, to_base64: bool = False) -> str` | HEX/Base64 密文 |
| **`decrypt_gcm_to_string` ⭐** | `@staticmethod decrypt_gcm_to_string(key: bytes, ciphertext_str: str) -> str` | UTF-8 明文 |

**调用示例**：

```python
from crossmool import SM4Util

key = SM4Util.generate_key()
encrypted = SM4Util.encrypt_gcm_string(key, "Hello, SM4!")
decrypted = SM4Util.decrypt_gcm_to_string(key, encrypted)
print(decrypted)  # Hello, SM4!
```

---

### 7.4 Python — 辅助函数

**模块**: `crossmool.encoding`

| 函数 | 签名 |
|------|------|
| `is_hex_string` | `(s: str) -> bool` |
| `is_base64_string` | `(s: str) -> bool` |
| `hex_to_bytes` | `(hex_str: str) -> bytes` |
| `bytes_to_hex` | `(b: bytes) -> str` |
| `base64_to_bytes` | `(s: str) -> bytes` |
| `bytes_to_base64` | `(b: bytes) -> str` |
| `detect_string_encoding` | `(s: str) -> "hex" \| "base64" \| "unknown"` |
| `utf8_to_bytes` | `(s: str) -> bytes` |
| `bytes_to_utf8` | `(b: bytes) -> str` |

**SM2 密钥转换函数** (`sm2_util` 模块):

| 函数 | 签名 |
|------|------|
| `sm2_public_key_to_raw_hex` | `(key_input) -> str` (uncompressed 格式: 04+X+Y) |
| `sm2_private_key_to_raw_hex` | `(key_input) -> str` (32 字节 HEX) |

---

## 8. Go 语言接口

**包名**: `crossmool`  
**导入**: `import "..."`（包路径取决于项目结构）  
**底层库**: `github.com/emmansun/gmsm`

### 8.1 Go — SM2

#### 8.1.1 类型定义

```go
type CiphertextSignaturePair struct {
    Ciphertext string
    Signature  string
}
```

#### 8.1.2 密钥生成

| 函数 | 签名 | 出参 |
|------|------|------|
| `GenerateKeyPair` | `func GenerateKeyPair() (pubDer []byte, privDer []byte, err error)` | X.509/PKCS#8 DER 编码 |
| `GenerateKeyPairHex` | `func GenerateKeyPairHex() (pubHex string, privHex string, err error)` | HEX 密钥 |
| `GenerateKeyPairBase64` | `func GenerateKeyPairBase64() (pubB64 string, privB64 string, err error)` | Base64 密钥 |

#### 8.1.3 底层字节接口

| 函数 | 签名 | 出参 |
|------|------|------|
| `EncryptBytes` | `func EncryptBytes(content []byte, pubDer []byte) ([]byte, error)` | C1C3C2 密文字节 |
| `DecryptBytes` | `func DecryptBytes(ciphertext []byte, privDer []byte) ([]byte, error)` | 明文字节 |
| `SignBytes` | `func SignBytes(content []byte, privDer []byte) ([]byte, error)` | ASN.1 签名字节 |
| `VerifyBytes` | `func VerifyBytes(content []byte, signature []byte, pubDer []byte) (bool, error)` | 验证结果 |

#### 8.1.4 字符串接口（推荐）

| 函数 | 签名 | 入参 | 出参 |
|------|------|------|------|
| `Encrypt` | `func Encrypt(content string, encPublicKey string, toBase64 bool) (string, error)` | `toBase64` — false=HEX, true=Base64 | HEX/Base64 密文 |
| **`EncryptDefault` ⭐** | `func EncryptDefault(content string, encPublicKey string) (string, error)` | HEX 公钥 | HEX 密文 |
| **`Decrypt` ⭐** | `func Decrypt(ciphertext string, privKey string) (string, error)` | 自动检测 HEX/Base64 | UTF-8 明文 |
| `Sign` | `func Sign(content string, signPrivateKey string, toBase64 bool) (string, error)` | `toBase64` — false=HEX, true=Base64 | HEX/Base64 签名 |
| **`SignDefault` ⭐** | `func SignDefault(content string, signPrivateKey string) (string, error)` | HEX/Base64 私钥 | HEX 签名 |
| **`Verify` ⭐** | `func Verify(content string, publicKey string, signature string) (bool, error)` | 自动检测 HEX/Base64 | 验证结果 |
| `EncryptSign` | `func EncryptSign(content string, encPublicKey string, signPrivateKey string, toBase64 bool) (*CiphertextSignaturePair, error)` | | 密文签名对 |
| **`EncryptSignDefault` ⭐** | `func EncryptSignDefault(content string, encPublicKey string, signPrivateKey string) (*CiphertextSignaturePair, error)` | | HEX 密文签名对 |
| **`VerifyDecrypt` ⭐** | `func VerifyDecrypt(ciphertext string, signature string, signPublicKey string, decPrivateKey string) (string, error)` | | UTF-8 明文 |
| `EncryptSignWithHexKeys` | `func EncryptSignWithHexKeys(content string, encPublicKey string, signPrivateKey string) (*CiphertextSignaturePair, error)` |
| `EncryptSignWithBase64Keys` | `func EncryptSignWithBase64Keys(content string, encPublicKey string, signPrivateKey string) (*CiphertextSignaturePair, error)` |
| `EncryptSignWithSameFormatKeys` | `func EncryptSignWithSameFormatKeys(content string, encPublicKey string, signPrivateKey string) (*CiphertextSignaturePair, error)` |
| `VerifyDecryptPair` | `func VerifyDecryptPair(pair *CiphertextSignaturePair, signPublicKey string, decPrivateKey string) (string, error)` |

**调用示例**：

```go
import "crossmool"

pubHex, privHex, _ := crossmool.GenerateKeyPairHex()

encrypted, _ := crossmool.EncryptDefault("Hello, SM2!", pubHex)
decrypted, _ := crossmool.Decrypt(encrypted, privHex)
fmt.Println(decrypted)  // Hello, SM2!

sig, _ := crossmool.SignDefault("Hello", privHex)
valid, _ := crossmool.Verify("Hello", pubHex, sig)
fmt.Println(valid)  // true
```

---

### 8.2 Go — SM3

| 函数 | 签名 | 出参 |
|------|------|------|
| `Digest` | `func Digest(data []byte) []byte` | 杂凑字节 |
| `DigestHex` | `func DigestHex(data []byte) string` | HEX 杂凑 |
| `DigestBase64` | `func DigestBase64(data []byte) string` | Base64 杂凑 |
| **`DigestToStr` ⭐** | `func DigestToStr(input string, toBase64 bool) string` | HEX/Base64 杂凑 |
| `HMAC` | `func HMAC(key, data []byte) []byte` | HMAC 字节 |
| **`HMACToStr` ⭐** | `func HMACToStr(key string, data string, toBase64 bool) (string, error)` | HEX/Base64 HMAC |
| `GenerateHmacKey` | `func GenerateHmacKey(length int) []byte` | 随机密钥（≥32字节） |
| `GenerateHmacKeyToStr` | `func GenerateHmacKeyToStr(length int, toBase64 bool) string` | HEX/Base64 密钥 |

**调用示例**：

```go
hash := crossmool.DigestToStr("Hello, SM3!", false)
fmt.Println(hash)  // HEX 杂凑值

key := crossmool.GenerateHmacKey(32)
mac, _ := crossmool.HMACToStr(EncodeHex(key), "data", false)
```

---

### 8.3 Go — SM4

| 函数 | 签名 | 出参 |
|------|------|------|
| `GenerateKey` | `func GenerateKey() ([]byte, error)` | 16 字节随机密钥 |
| `EncryptGcm` | `func EncryptGcm(key, plain []byte, toBase64 bool) (string, error)` | HEX/Base64 密文 |
| `EncryptGcmWithIV` | `func EncryptGcmWithIV(key, plain, iv []byte, toBase64 bool) (string, error)` | HEX/Base64 密文 |
| `EncryptGcmHex` | `func EncryptGcmHex(key, plain []byte) (string, error)` | HEX 密文 |
| `DecryptGcm` | `func DecryptGcm(key []byte, encodedData string) ([]byte, error)` | 明文字节（自动检测） |
| `DecryptGcmHex` | `func DecryptGcmHex(key []byte, hexStr string) ([]byte, error)` | 明文字节 |
| **`DecryptGcmToString` ⭐** | `func DecryptGcmToString(key []byte, encodedData string) (string, error)` | UTF-8 明文 |

**调用示例**：

```go
key, _ := crossmool.GenerateKey()
encrypted, _ := crossmool.EncryptGcm(key, []byte("Hello, SM4!"), false)
decrypted, _ := crossmool.DecryptGcmToString(key, encrypted)
fmt.Println(decrypted)  // Hello, SM4!
```

---

### 8.4 Go — 工具函数

| 函数 | 签名 |
|------|------|
| `IsHexString` | `func IsHexString(s string) bool` |
| `IsBase64String` | `func IsBase64String(s string) bool` |
| `DecodeHexString` | `func DecodeHexString(s string) ([]byte, error)` |
| `EncodeHex` | `func EncodeHex(data []byte) string` |
| `DecodeBase64String` | `func DecodeBase64String(s string) ([]byte, error)` |
| `EncodeBase64` | `func EncodeBase64(data []byte) string` |
| `ConvertStringToBytes` | `func ConvertStringToBytes(s string) ([]byte, error)` |

---

## 9. Rust 语言接口

**Crate**: `crossmool`  
**模块**: `sm2`, `sm3`, `sm4`, `encoding`  
**底层库**: `sm2`, `sm3`, `sm4`, `hmac`

### 9.1 Rust — SM2 模块

#### 9.1.1 类型定义

```rust
#[derive(Debug, Clone)]
pub struct SerialKeyPair {
    pub public_key_pem: String,
    pub private_key_pem: String,
}
```

#### 9.1.2 密钥生成

| 函数 | 签名 | 出参 |
|------|------|------|
| `generate_keypair` | `pub fn generate_keypair() -> Result<SerialKeyPair, String>` | PEM 编码密钥对 |

#### 9.1.3 加密 / 解密

| 函数 | 签名 | 出参 |
|------|------|------|
| `encrypt_with_public_pem` | `pub fn encrypt_with_public_pem(public_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, String>` | C1C3C2 密文字节 |
| `encrypt_with_public_pem_hex` | `pub fn encrypt_with_public_pem_hex(public_pem: &str, plaintext: &[u8]) -> Result<String, String>` | HEX 密文 |
| `encrypt_with_public_pem_base64` | `pub fn encrypt_with_public_pem_base64(public_pem: &str, plaintext: &[u8]) -> Result<String, String>` | Base64 密文 |
| `decrypt_with_private_pem` | `pub fn decrypt_with_private_pem(private_pem: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String>` | 明文字节 |
| `decrypt_with_private_pem_hex` | `pub fn decrypt_with_private_pem_hex(private_pem: &str, ciphertext_hex: &str) -> Result<Vec<u8>, String>` | 明文字节 |
| `decrypt_with_private_pem_base64` | `pub fn decrypt_with_private_pem_base64(private_pem: &str, ciphertext_b64: &str) -> Result<Vec<u8>, String>` | 明文字节 |
| `encrypt_with_publickey` | `pub fn encrypt_with_publickey(pk: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, String>` | C1C3C2 密文字节 |

#### 9.1.4 签名 / 验签

| 函数 | 签名 | 出参 |
|------|------|------|
| `sign_bytes` | `pub fn sign_bytes(msg: &[u8], private_pkcs8_der: &[u8]) -> Result<Vec<u8>, String>` | 签名字节（64 字节） |
| `sign_with_private_pem` | `pub fn sign_with_private_pem(msg: &[u8], private_pkcs8_pem: &str) -> Result<Vec<u8>, String>` | 签名字节 |
| `verify_with_public_pem` | `pub fn verify_with_public_pem(msg: &[u8], signature: &[u8], public_pem: &str) -> Result<bool, String>` | 验证结果 |
| `verify_bytes` | `pub fn verify_bytes(msg: &[u8], signature: &[u8], public_x509_der: &[u8]) -> Result<bool, String>` | 验证结果 |

**调用示例**：

```rust
use crossmool::sm2;

let keypair = sm2::generate_keypair().unwrap();
println!("Public: {}", keypair.public_key_pem);
println!("Private: {}", keypair.private_key_pem);

let ct_hex = sm2::encrypt_with_public_pem_hex(
    &keypair.public_key_pem,
    b"Hello, SM2!"
).unwrap();

let plain = sm2::decrypt_with_private_pem_hex(
    &keypair.private_key_pem,
    &ct_hex
).unwrap();
println!("{}", String::from_utf8_lossy(&plain));

let sig = sm2::sign_with_private_pem(b"Hello", &keypair.private_key_pem).unwrap();
let valid = sm2::verify_with_public_pem(b"Hello", &sig, &keypair.public_key_pem).unwrap();
```

---

### 9.2 Rust — SM3 模块

#### 杂凑

| 函数 | 签名 | 出参 |
|------|------|------|
| `digest_bytes` | `pub fn digest_bytes(data: &[u8]) -> Vec<u8>` | 杂凑字节 |
| `digest_hex` | `pub fn digest_hex(data: &[u8]) -> String` | HEX 杂凑 |
| `digest_base64` | `pub fn digest_base64(data: &[u8]) -> String` | Base64 杂凑 |
| `digest_to_str` | `pub fn digest_to_str(data: &[u8], to_base64: bool) -> String` | HEX/Base64 杂凑 |
| `digest_str` | `pub fn digest_str(input: &str, to_base64: bool) -> String` | HEX/Base64 杂凑 |
| **`digest_str_default` ⭐** | `pub fn digest_str_default(input: &str) -> String` | HEX 杂凑（默认） |

#### HMAC-SM3

| 函数 | 签名 | 出参 |
|------|------|------|
| `hmac_bytes` | `pub fn hmac_bytes(key: &[u8], data: &[u8]) -> Vec<u8>` | HMAC 字节 |
| `hmac_hex` | `pub fn hmac_hex(key: &[u8], data: &[u8]) -> String` | HEX HMAC |
| `hmac_base64` | `pub fn hmac_base64(key: &[u8], data: &[u8]) -> String` | Base64 HMAC |
| `hmac_to_str` | `pub fn hmac_to_str(key: &[u8], data: &[u8], to_base64: bool) -> String` | HEX/Base64 HMAC |
| `hmac_from_str` | `pub fn hmac_from_str(key: &str, data: &str) -> Result<Vec<u8>, String>` | HMAC 字节 |
| **`hmac_str` ⭐** | `pub fn hmac_str(key: &str, data: &str, to_base64: bool) -> Result<String, String>` | HEX/Base64 HMAC |
| `hmac_str_default` | `pub fn hmac_str_default(key: &str, data: &str) -> Result<String, String>` | HEX HMAC（默认） |
| `generate_hmac_key` | `pub fn generate_hmac_key(length: usize) -> Vec<u8>` | 随机密钥（≥32 字节） |
| `generate_hmac_key_to_str` | `pub fn generate_hmac_key_to_str(length: usize, to_base64: bool) -> String` | HEX/Base64 密钥 |
| `generate_hmac_key_str` | `pub fn generate_hmac_key_str(to_base64: bool) -> String` | HEX/Base64 32 字节密钥 |

---

### 9.3 Rust — SM4 模块

| 函数 | 签名 | 出参 |
|------|------|------|
| `generate_key` | `pub fn generate_key() -> Vec<u8>` | 16 字节随机密钥 |
| `encrypt_gcm` | `pub fn encrypt_gcm(key: &[u8], plain: &[u8], to_base64: bool) -> Result<String, String>` | HEX/Base64 密文 |
| `encrypt_gcm_with_iv` | `pub fn encrypt_gcm_with_iv(key: &[u8], plain: &[u8], iv: &[u8], to_base64: bool) -> Result<String, String>` | HEX/Base64 密文 |
| `encrypt_gcm_hex` | `pub fn encrypt_gcm_hex(key: &[u8], plain: &[u8]) -> Result<String, String>` | HEX 密文 |
| `encrypt_gcm_hex_with_iv` | `pub fn encrypt_gcm_hex_with_iv(key: &[u8], plain: &[u8], iv: &[u8]) -> Result<String, String>` | HEX 密文 |
| `encrypt_gcm_base64` | `pub fn encrypt_gcm_base64(key: &[u8], plain: &[u8]) -> Result<String, String>` | Base64 密文 |
| `encrypt_gcm_base64_with_iv` | `pub fn encrypt_gcm_base64_with_iv(key: &[u8], plain: &[u8], iv: &[u8]) -> Result<String, String>` | Base64 密文 |
| `decrypt_gcm` | `pub fn decrypt_gcm(key: &[u8], encoded: &str) -> Result<Vec<u8>, String>` | 明文字节（自动检测） |
| `decrypt_gcm_from_hex` | `pub fn decrypt_gcm_from_hex(key: &[u8], hex_str: &str) -> Result<Vec<u8>, String>` | 明文字节 |
| `decrypt_gcm_base64` | `pub fn decrypt_gcm_base64(key: &[u8], encoded: &str) -> Result<Vec<u8>, String>` | 明文字节 |
| **`encrypt_gcm_string` ⭐** | `pub fn encrypt_gcm_string(key: &[u8], plain: &str, to_base64: bool) -> Result<String, String>` | HEX/Base64 密文 |
| **`decrypt_gcm_to_string` ⭐** | `pub fn decrypt_gcm_to_string(key: &[u8], encoded: &str) -> Result<String, String>` | UTF-8 明文 |
| **`decrypt_gcm_base64_to_string` ⭐** | `pub fn decrypt_gcm_base64_to_string(key: &[u8], encoded: &str) -> Result<String, String>` | UTF-8 明文 |

**调用示例**：

```rust
use crossmool::sm4;

let key = sm4::generate_key();
let encrypted = sm4::encrypt_gcm_string(&key, "Hello, SM4!", false).unwrap();
let decrypted = sm4::decrypt_gcm_to_string(&key, &encrypted).unwrap();
println!("{}", decrypted);  // Hello, SM4!
```

---

### 9.4 Rust — Encoding 模块

| 函数 | 签名 |
|------|------|
| `to_hex` | `pub fn to_hex(bytes: &[u8]) -> String` |
| `from_hex` | `pub fn from_hex(hexstr: &str) -> Result<Vec<u8>, hex::FromHexError>` |
| `to_base64` | `pub fn to_base64(bytes: &[u8]) -> String` |
| `from_base64` | `pub fn from_base64(b64: &str) -> Result<Vec<u8>, base64::DecodeError>` |
| `is_hex` | `pub fn is_hex(s: &str) -> bool` |
| `is_base64` | `pub fn is_base64(s: &str) -> bool` |

---

## 10. JavaScript/TypeScript 语言接口

**包名**: `crossmool`  
**导入**: `import { SM2Util, SM3Util, SM4Util } from 'crossmool'`  
**底层库**: `sm-crypto-v2`

### 10.1 JS — SM2Util

**类**: `export class SM2Util`（所有方法为 `static`）

**类型定义**：

```typescript
export interface CiphertextSignaturePair {
  ciphertext: string;
  signature: string;
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}
```

#### 10.1.1 密钥生成

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateKeyPairHex` | `static generateKeyPairHex(): KeyPair` | `KeyPair{ publicKey, privateKey }`（公钥 130 字符 hex，私钥 64 字符 hex） |

#### 10.1.2 加密 / 解密

| 方法 | 签名 | 出参 |
|------|------|------|
| `encryptToBytes` | `static encryptToBytes(content: Uint8Array, publicKey: KeyInput): Uint8Array` | 密文字节 |
| `encryptToHex` | `static encryptToHex(content: string \| Uint8Array, publicKey: KeyInput): string` | HEX 密文 |
| `encryptToBase64` | `static encryptToBase64(content: string \| Uint8Array, publicKey: KeyInput): string` | Base64 密文 |
| **`encrypt` ⭐** | `static encrypt(content: string, publicKey: KeyInput, toBase64 = false): string` | HEX/Base64 密文 |
| `decryptToBytes` | `static decryptToBytes(cipherBytes: Uint8Array, privateKey: KeyInput): Uint8Array` | 明文字节 |
| `decryptToUtf8` | `static decryptToUtf8(cipherHexOrBase64: string, privateKey: KeyInput): string` | UTF-8 明文 |
| `decryptToBytesFromString` | `static decryptToBytesFromString(cipherHexOrBase64: string, privateKey: KeyInput): Uint8Array` | 明文字节 |
| **`decrypt` ⭐** | `static decrypt(cipherHexOrBase64: string, privateKey: KeyInput): string` | UTF-8 明文 |

#### 10.1.3 签名 / 验签

| 方法 | 签名 | 出参 |
|------|------|------|
| `signToBytes` | `static signToBytes(content: Uint8Array, privateKey: KeyInput): Uint8Array` | 签名字节 |
| `signToHex` | `static signToHex(content: string \| Uint8Array, privateKey: KeyInput): string` | HEX 签名 |
| `signToBase64` | `static signToBase64(content: string \| Uint8Array, privateKey: KeyInput): string` | Base64 签名 |
| **`sign` ⭐** | `static sign(content: string, privateKey: KeyInput, toBase64 = false): string` | HEX/Base64 签名 |
| **`verify` ⭐** | `static verify(content: string \| Uint8Array, publicKey: KeyInput, signatureHexOrBase64: string): boolean` | 验证结果 |

#### 10.1.4 加密签名组合

| 方法 | 签名 |
|------|------|
| **`encryptSign` ⭐** | `static encryptSign(content: string, encPublicKey: KeyInput, signPrivateKey: KeyInput, toBase64 = false): CiphertextSignaturePair` |
| `encryptSignWithSameFormatKeys` | `static encryptSignWithSameFormatKeys(content: string, encPublicKey: string, signPrivateKey: string): CiphertextSignaturePair` |
| **`verifyDecrypt` ⭐** | `static verifyDecrypt(ciphertext: string, signature: string, signPublicKey: KeyInput, decPrivateKey: KeyInput): string` |
| `verifyDecryptPair` | `static verifyDecryptPair(pair: CiphertextSignaturePair, signPublicKey: KeyInput, decPrivateKey: KeyInput): string` |

**调用示例**：

```typescript
import { SM2Util } from 'crossmool';

// 加密/解密
const encrypted = SM2Util.encrypt('Hello, SM2!', publicKeyHex);
const decrypted = SM2Util.decrypt(encrypted, privateKeyHex);
console.log(decrypted);  // Hello, SM2!

// 签名/验签
const sig = SM2Util.sign('Hello', privateKeyHex);
const valid = SM2Util.verify('Hello', publicKeyHex, sig);
console.log(valid);  // true

// 加密签名组合
const pair = SM2Util.encryptSign('Hello', encPubKey, signPrivKey);
const plain = SM2Util.verifyDecrypt(pair.ciphertext, pair.signature, signPubKey, decPrivKey);
```

---

### 10.2 JS — SM3Util

**类**: `export class SM3Util`

#### 杂凑

| 方法 | 签名 | 出参 |
|------|------|------|
| `digestToBytes` | `static digestToBytes(input: Uint8Array): Uint8Array` | 杂凑字节 |
| `digestToHex` | `static digestToHex(input: Uint8Array \| string): string` | HEX 杂凑 |
| `digestToBase64` | `static digestToBase64(input: Uint8Array \| string): string` | Base64 杂凑 |
| `digestFromBase64ToHex` | `static digestFromBase64ToHex(base64: string): string` | HEX 杂凑 |
| **`digest` ⭐** | `static digest(input: Uint8Array \| string, toBase64 = false): string` | HEX/Base64 杂凑 |

#### HMAC-SM3

| 方法 | 签名 | 出参 |
|------|------|------|
| `hmacBytes` | `static hmacBytes(key: Uint8Array, data: Uint8Array): Uint8Array` | HMAC 字节 |
| `hmacToHex` | `static hmacToHex(key: Uint8Array \| string, data: Uint8Array \| string): string` | HEX HMAC |
| `hmacToBase64` | `static hmacToBase64(key: Uint8Array \| string, data: Uint8Array \| string): string` | Base64 HMAC |
| **`hmac` ⭐** | `static hmac(key: Uint8Array \| string, data: Uint8Array \| string, toBase64 = false): string` | HEX/Base64 HMAC |
| `generateHmacKeyBytes` | `static generateHmacKeyBytes(keyLength = 32): Uint8Array` | 随机密钥 |
| `generateHmacKeyHex` | `static generateHmacKeyHex(keyLength = 32): string` | HEX 密钥 |
| `generateHmacKeyBase64` | `static generateHmacKeyBase64(keyLength = 32): string` | Base64 密钥 |
| `generateHmacKeyToStr` | `static generateHmacKeyToStr(keyLength: number \| boolean = 32, toBase64 = false): string` | HEX/Base64 密钥 |
| `hmacVerify` | `static hmacVerify(key: Uint8Array \| string, data: Uint8Array \| string, receivedHmac: string): boolean` | 验证结果 |

---

### 10.3 JS — SM4Util

**类**: `export class SM4Util`

| 方法 | 签名 | 出参 |
|------|------|------|
| `generateKeyBytes` | `static generateKeyBytes(): Uint8Array` | 16 字节随机密钥 |
| `generateKeyHex` | `static generateKeyHex(): string` | HEX 密钥 |
| `generateKeyBase64` | `static generateKeyBase64(): string` | Base64 密钥 |
| `parseHexKey` | `static parseHexKey(hexKey: string): Uint8Array` | 解析后的密钥 |
| `generateGcmIV` | `static generateGcmIV(): Uint8Array` | 12 字节随机 IV |
| `encryptGcm` | `static encryptGcm(plaintext: Uint8Array, key: Uint8Array \| string, iv?: Uint8Array, toBase64 = false): string` | HEX/Base64 密文 |
| `encryptGcmHex` | `static encryptGcmHex(plaintext: Uint8Array, key: Uint8Array \| string, iv?: Uint8Array): string` | HEX 密文 |
| `encryptGcmBase64` | `static encryptGcmBase64(plaintext: Uint8Array, key: Uint8Array \| string, iv?: Uint8Array): string` | Base64 密文 |
| `decryptGcm` | `static decryptGcm(ciphertextHexOrBase64: string, key: Uint8Array \| string): Uint8Array` | 明文字节（自动检测） |
| `decryptGcmFromHex` | `static decryptGcmFromHex(ciphertextHex: string, key: Uint8Array \| string): Uint8Array` | 明文字节 |
| **`encryptGcmString` ⭐** | `static encryptGcmString(plainText: string, key: Uint8Array \| string, iv?: Uint8Array, toBase64 = false): string` | HEX/Base64 密文 |
| **`decryptGcmToString` ⭐** | `static decryptGcmToString(ciphertextHexOrBase64: string, key: Uint8Array \| string): string` | UTF-8 明文 |

**调用示例**：

```typescript
import { SM4Util } from 'crossmool';

const encrypted = SM4Util.encryptGcmString('Hello, SM4!', keyHex);
const decrypted = SM4Util.decryptGcmToString(encrypted, keyHex);
console.log(decrypted);  // Hello, SM4!
```

---

### 10.4 JS — 工具函数

**导出位置**: `crossmool` 包的顶层导出

| 函数 | 签名 |
|------|------|
| `bytesToBase64` | `(bytes: Bytes) => string` |
| `bytesToHex` | `(bytes: Bytes) => string` |
| `base64ToBytes` | `(base64: string) => Bytes` |
| `hexToBytes` | `(hex: string) => Bytes` |
| `isBase64String` | `(input: string) => boolean` |
| `isHexString` | `(input: string) => boolean` |
| `utf8ToBytes` | `(text: string) => Bytes` |
| `bytesToUtf8` | `(bytes: Bytes) => string` |
| `decodeHexOrBase64ToBytes` | `(input: string) => Bytes` |
| `sm2PublicKeyToRawHex` | `(publicKey: KeyInput) => string` |
| `sm2PrivateKeyToRawHex` | `(privateKey: KeyInput) => string` |

---

## 附录 A: 错误码参考

**适用范围**: C 语言接口

| 错误码 | 常量名 | 含义 |
|--------|--------|------|
| 0 | `CROSSMOOL_SUCCESS` | 成功 |
| -1 | `CROSSMOOL_ERR_INVALID_PARAM` | 参数错误 |
| -2 | `CROSSMOOL_ERR_MEMORY_ALLOC` | 内存分配失败 |
| -3 | `CROSSMOOL_ERR_ENCRYPT_DECRYPT` | 加密/解密失败 |
| -4 | `CROSSMOOL_ERR_SIGN_VERIFY` | 签名/验签失败 |
| -5 | `CROSSMOOL_ERR_FORMAT_CONVERSION` | 格式转换错误 |
| -6 | `CROSSMOOL_ERR_KEY_INVALID` | 密钥无效 |
| -7 | `CROSSMOOL_ERR_CHARSET_INVALID` | 字符集不支持 |

> 其他语言通过异常（Java/C#/Python）、错误返回值（Go/Rust/JS）或异常抛出方式处理错误。

---

## 附录 B: 数据格式说明

### B.1 SM2 C1C3C2 密文格式

```
C1(65字节: 04 + X坐标32字节 + Y坐标32字节) + C3(32字节: SM3哈希) + C2(与明文等长)
```

### B.2 SM2 签名格式

- DER 编码: `30 || len || 02 || r_len || r || 02 || s_len || s`（与 Java BouncyCastle 兼容）
- USER_ID 固定为 `"1234567812345678"`（GB/T 32918 标准）

### B.3 SM4 GCM 密文格式

```
IV(12字节) + 密文(N字节) + Tag(16字节)
```

编码为 HEX 或 Base64 后输出，解密时自动检测编码格式。

### B.4 SM2 密钥格式

| 格式 | 公钥 | 私钥 |
|------|------|------|
| X.509 / PKCS#8 | SubjectPublicKeyInfo DER | PrivateKeyInfo DER |
| 原始 HEX | 130 字符 (04+X+Y) | 64 字符 |

### B.5 SM4 密钥格式

16 字节（128 bits）原始密钥，可表示为 32 字符 HEX 或 Base64 字符串。

---

> **文档结束** — 如有问题请参考各语言目录下的 README.md 或示例代码。
