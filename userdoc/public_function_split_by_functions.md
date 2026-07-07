# Crossmool 函数索引（按功能聚合）

> **版本**: v1.0 | **文档日期**: 2026-07-07
>
> 本文档以 **功能** 为索引维度，将 8 种编程语言（C / C++ / C# / Java / Python / JavaScript / Go / Rust）中相同功能的公有方法聚合在一起。
>
> **阅读方式**: 一级目录 = 功能类别（如 SM2 加密）；二级目录 = 具体函数（如 `SM2_encrypt_utf8_to_hex`）；三级目录 = 各语言对应的调用方式。
>
> 函数命名的含义：`算法_操作_输入格式_to_输出格式`
> - `utf8` = 字符串输入/输出（UTF-8 编码）
> - `bytes` = 字节数组/二进制原始输入输出
> - `hex` = HEX 编码字符串
> - `base64` = Base64 编码字符串

---

## 目录

- [1. SM2 密钥生成](#1-sm2-密钥生成)
- [2. SM2 加密](#2-sm2-加密)
- [3. SM2 解密](#3-sm2-解密)
- [4. SM2 签名](#4-sm2-签名)
- [5. SM2 验签](#5-sm2-验签)
- [6. SM2 加密并签名](#6-sm2-加密并签名)
- [7. SM2 验签并解密](#7-sm2-验签并解密)
- [8. SM3 杂凑](#8-sm3-杂凑)
- [9. SM3 HMAC 密钥生成](#9-sm3-hmac-密钥生成)
- [10. SM3 HMAC 计算](#10-sm3-hmac-计算)
- [11. SM3 HMAC 验证](#11-sm3-hmac-验证)
- [12. SM4 密钥管理](#12-sm4-密钥管理)
- [13. SM4 GCM 加密](#13-sm4-gcm-加密)
- [14. SM4 GCM 解密](#14-sm4-gcm-解密)
- [15. 工具函数](#15-工具函数)
- [附录: 快速查询表](#附录-快速查询表)

---

## 1. SM2 密钥生成

### SM2_generate_keypair

> 生成 SM2 密钥对（公钥 + 私钥）。返回格式取决于具体语言和调用方法。

#### SM2_generate_keypair_raw

生成原始密钥对（PEM / DER / 原始 HEX 格式）。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_generate_keypair(&keypair)` → 填充 `keypair->public_key` / `keypair->private_key`（DER 编码） |
| **C++** | `SM2Util::generateKeyPairRaw()` → `KeyPair{ publicKey, privateKey }`（HEX of X.509 / PKCS#8 DER） |
| **C#** | `SM2Util.generateKeyPair()` → JSON 字符串 `{"publicKeyHex":"...", "privateKeyHex":"..."}` |
| **Java** | `SM2Util.generateKeyPair()` → `java.security.KeyPair` 对象 |
| **Python** | `SM2Util.generate_keypair_raw()` → `(private_hex, public_hex)` 元组 |
| **Go** | `GenerateKeyPair()` → `(pubDer []byte, privDer []byte, error)` |
| **Rust** | `sm2::generate_keypair()` → `Result<SerialKeyPair, String>`（PEM 格式） |

> **说明**: C++ `generateKeyPairRaw()` 返回的公钥为 **X.509 SubjectPublicKeyInfo DER** 的 HEX 编码，私钥为 **PKCS#8 PrivateKeyInfo DER** 的 HEX 编码，与 Go 的 `GenerateKeyPair()` 输出格式一致。

#### SM2_generate_keypair_hex

生成 HEX 编码的密钥对（公钥和私钥均为 HEX 字符串）。

| 语言 | 调用方式 | 返回值 |
|------|----------|--------|
| **C** | `crossmool_sm2_generate_keypair_hex(&keypair)` | `keypair.public_key_hex` / `keypair.private_key_hex` |
| **C++** | `SM2Util::generateKeyPairHex()` | `KeyPair{ publicKey, privateKey }` |
| **Java** | `SM2Util.generateKeyPairHex()` | `SerialKeyPair` 对象（`.getPublicKey()` / `.getPrivateKey()`） |
| **JavaScript** | `SM2Util.generateKeyPairHex()` | `KeyPair{ publicKey, privateKey }`（公钥 130 字符，私钥 64 字符） |
| **Go** | `GenerateKeyPairHex()` | `(pubHex string, privHex string, error)` |

#### SM2_generate_keypair_base64

生成 Base64 编码的密钥对。

| 语言 | 调用方式 | 返回值 |
|------|----------|--------|
| **C** | `crossmool_sm2_generate_keypair_base64(&keypair)` | `keypair.public_key_base64` / `keypair.private_key_base64` |
| **C++** | `SM2Util::generateKeyPairBase64()` | `KeyPair{ publicKey, privateKey }` |
| **Java** | `SM2Util.generateKeyPairBase64()` | `SerialKeyPair` 对象 |
| **Go** | `GenerateKeyPairBase64()` | `(pubB64 string, privB64 string, error)` |

#### SM2_export_private_key_pem / SM2_export_public_key_pem

导出 PEM 格式密钥（仅部分语言支持）。

| 语言 | 导出私钥 | 导出公钥 |
|------|----------|----------|
| **C#** | `SM2Util.exportPrivateKeyPem(byte[])` → string | `SM2Util.exportPublicKeyPem(byte[])` → string |
| **Rust** | `sm2::generate_keypair()` → `SerialKeyPair{ private_key_pem, public_key_pem }` | 同上 |

#### SM2_import_private_key_pem / SM2_import_public_key_pem

导入 PEM 格式密钥（仅部分语言支持）。

| 语言 | 导入私钥 | 导入公钥 |
|------|----------|----------|
| **C#** | `SM2Util.importPrivateKeyPem(string)` → byte[] | `SM2Util.importPublicKeyPem(string)` → byte[] |

---

## 2. SM2 加密

### SM2_encrypt_utf8_to_hex

> 明文为 UTF-8 字符串，公钥为 HEX/Base64 字符串（自动检测），输出 HEX 密文。

| 语言 | 调用方式 | 参数说明 |
|------|----------|----------|
| **C** | `crossmool_sm2_encrypt(content, NULL, public_key, &ciphertext_hex)` | `content`: 明文字符串, `NULL`: UTF-8 字符集, `public_key`: HEX/Base64 公钥 |
| **C++** | `SM2Util::encrypt(content, public_key)` 或 `SM2Util::encryptToHex(content, public_key)` | `content`: string, `public_key`: string |
| **C#** | `SM2Util.encryptToHex(originalText, publicKeyString)` | `originalText`: string, `publicKeyString`: string |
| **Java** | `SM2Util.encrypt(content, publicKey)` 或 `SM2Util.encryptToHex(content, publicKey)` | `content`: String, `publicKey`: String |
| **Python** | `SM2Util.encrypt(content, public_key)` | `content`: str, `public_key`: str (HEX/Base64/bytes) |
| **JavaScript** | `SM2Util.encrypt(content, publicKey)` 或 `SM2Util.encryptToHex(content, publicKey)` | `content`: string, `publicKey`: KeyInput |
| **Go** | `Encrypt(content, encPublicKey, false)` 或 `EncryptDefault(content, encPublicKey)` | `content`: string, `encPublicKey`: string, `false`: HEX 输出 |
| **Rust** | `sm2::encrypt_with_public_pem_hex(public_pem, plaintext)` | `public_pem`: &str, `plaintext`: &[u8]（需手动 utf8 编码） |

**调用示例**:

```c
// C
char* ct = NULL;
crossmool_sm2_encrypt("Hello, SM2!", NULL, public_key_hex, &ct);
free(ct);
```

```cpp
// C++
std::string ct = SM2Util::encrypt("Hello, SM2!", publicKey);
```

```csharp
// C#
string ct = SM2Util.encryptToHex("Hello, SM2!", publicKeyHex);
```

```java
// Java
String ct = SM2Util.encrypt("Hello, SM2!", publicKey);
```

```python
# Python
ct = SM2Util.encrypt("Hello, SM2!", pub_hex)
```

```typescript
// JavaScript / TypeScript
const ct = SM2Util.encrypt('Hello, SM2!', publicKeyHex);
```

```go
// Go
ct, _ := crossmool.EncryptDefault("Hello, SM2!", pubHex)
```

```rust
// Rust
let ct = sm2::encrypt_with_public_pem_hex(&keypair.public_key_pem, b"Hello, SM2!").unwrap();
```

---

### SM2_encrypt_utf8_to_base64

> 明文为 UTF-8 字符串，公钥为 HEX/Base64 字符串（自动检测），输出 Base64 密文。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_encrypt_to_base64(content, content_len, charset, public_key, &ciphertext_b64)` |
| **C++** | `SM2Util::encrypt(content, public_key, true)` 或 `SM2Util::encryptToBase64(content, public_key)` |
| **C#** | `SM2Util.encryptToBase64(originalText, publicKeyString)` |
| **Java** | `SM2Util.encrypt(content, publicKey, true)` 或 `SM2Util.encryptToBase64(content, publicKey)` |
| **Python** | `SM2Util.encrypt(content, public_key, to_base64=True)` |
| **JavaScript** | `SM2Util.encrypt(content, publicKey, true)` 或 `SM2Util.encryptToBase64(content, publicKey)` |
| **Go** | `Encrypt(content, encPublicKey, true)` |
| **Rust** | `sm2::encrypt_with_public_pem_base64(public_pem, plaintext)` |

---

### SM2_encrypt_bytes_to_hex

> 明文为字节数组，公钥为 HEX/Base64 字符串（自动检测），输出 HEX 密文。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_encrypt_to_hex(content, content_len, charset, public_key, &ciphertext_hex)` |
| **C++** | `SM2Util::encryptToHex(content, publicKey)` (string 重载) 或先转 HexUtil |
| **Java** | `SM2Util.encryptToHex(content, publicKey)` (String 重载) |
| **Python** | `SM2Util.encrypt_to_hex(content, public_key)` → content: bytes |
| **JavaScript** | `SM2Util.encryptToHex(content, publicKey)` → content: Uint8Array |
| **Go** | `Encrypt(string(content), encPublicKey, false)` (需先 string 转换) |
| **Rust** | `sm2::encrypt_with_public_pem_hex(public_pem, plaintext)` |

---

### SM2_encrypt_bytes_to_base64

> 明文为字节数组，公钥为 HEX/Base64 字符串（自动检测），输出 Base64 密文。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_encrypt_to_base64(content, content_len, charset, public_key, &ciphertext_b64)` |
| **C++** | `SM2Util::encryptToBase64(content, publicKey)` |
| **Java** | `SM2Util.encryptToBase64(content, publicKey)` |
| **Python** | `SM2Util.encrypt_to_base64(content, public_key)` |
| **JavaScript** | `SM2Util.encryptToBase64(content, publicKey)` |
| **Go** | `Encrypt(string(content), encPublicKey, true)` |
| **Rust** | `sm2::encrypt_with_public_pem_base64(public_pem, plaintext)` |

---

### SM2_encrypt_bytes_to_bytes

> 明文为字节数组，公钥为字节数组（DER），输出密文字节数组（C1C3C2）。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_encrypt_bytes(content, content_len, public_key, &ciphertext, &ciphertext_len)` |
| **C++** | `SM2Util::encryptToBytes(content_bytes, publicKey_bytes)` |
| **C#** | `SM2Util.encrypt(originalTextBytes, publicKeyBytes)` → byte[] |
| **Java** | `SM2Util.encryptToBytes(content, publicKey)` → byte[] |
| **JavaScript** | `SM2Util.encryptToBytes(content, publicKey)` → Uint8Array |
| **Go** | `EncryptBytes(content, pubDer)` → []byte |
| **Rust** | `sm2::encrypt_with_public_pem(public_pem, plaintext)` 或 `sm2::encrypt_with_publickey(pk, plaintext)` |

---

## 3. SM2 解密

### SM2_decrypt_hex_to_utf8

> 输入 HEX 编码密文，私钥为 HEX/Base64 字符串（自动检测），输出 UTF-8 明文。

| 语言 | 调用方式 | 参数说明 |
|------|----------|----------|
| **C** | `crossmool_sm2_decrypt(ciphertext_hex, private_key, NULL, &plaintext)`, `crossmool_sm2_decrypt_to_string(ciphertext_hex, private_key, NULL, &plaintext)` | `ciphertext_hex`: HEX 密文字符串, `NULL`: UTF-8 |
| **C++** | `SM2Util::decrypt(ciphertext, privateKey)` | 自动检测 HEX/Base64 |
| **C#** | `SM2Util.decryptFromHex(encryptedTextHex, privateKeyString)` | 明确指定 HEX 输入 |
| **Java** | `SM2Util.decrypt(ciphertext, privateKey)` | 自动检测 HEX/Base64 |
| **Python** | `SM2Util.decrypt(cipher_text, private_key)` | 自动检测 HEX/Base64 |
| **JavaScript** | `SM2Util.decrypt(cipherHex, privateKey)` | 自动检测 HEX/Base64 |
| **Go** | `Decrypt(ciphertext, privKey)` | 自动检测 HEX/Base64 |
| **Rust** | `sm2::decrypt_with_private_pem_hex(private_pem, ciphertext_hex)` → Vec\<u8\>（需手动 utf8 解码） |

**调用示例**:

```c
// C
char* pt = NULL;
crossmool_sm2_decrypt(ciphertext_hex, private_key, NULL, &pt);
printf("%s\n", pt);
free(pt);
```

```cpp
// C++
std::string pt = SM2Util::decrypt(ciphertext, privateKey);
```

```csharp
// C#
string pt = SM2Util.decryptFromHex(ctHex, privateKeyHex);
```

```java
// Java
String pt = SM2Util.decrypt(ciphertext, privateKey);
```

```python
# Python
pt = SM2Util.decrypt(ct_hex, priv_hex)
```

```typescript
// JavaScript / TypeScript
const pt = SM2Util.decrypt(ctHex, privateKeyHex);
```

```go
// Go
pt, _ := crossmool.Decrypt(ctHex, privHex)
```

```rust
// Rust
let pt = sm2::decrypt_with_private_pem_hex(&keypair.private_key_pem, &ct_hex).unwrap();
println!("{}", String::from_utf8_lossy(&pt));
```

---

### SM2_decrypt_base64_to_utf8

> 输入 Base64 编码密文，私钥为 HEX/Base64 字符串（自动检测），输出 UTF-8 明文。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_decrypt_to_string(ciphertext_b64, private_key, NULL, &plaintext)` |
| **C++** | `SM2Util::decrypt(ciphertext, privateKey)` (自动检测) |
| **C#** | `SM2Util.decrypt(encryptedText, privateKeyString)` (自动检测) |
| **Java** | `SM2Util.decrypt(ciphertext, privateKey)` (自动检测) |
| **Python** | `SM2Util.decrypt(cipher_text, private_key)` (自动检测) |
| **JavaScript** | `SM2Util.decrypt(cipherBase64, privateKey)` (自动检测) |
| **Go** | `Decrypt(ciphertext, privKey)` (自动检测) |
| **Rust** | `sm2::decrypt_with_private_pem_base64(private_pem, ciphertext_b64)` |

---

### SM2_decrypt_hex_to_bytes

> 输入 HEX 编码密文，私钥为 HEX/Base64 字符串，输出明文字节数组。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_decrypt_bytes(ciphertext_hex, private_key, &plaintext, &plaintext_len)` |
| **C++** | `SM2Util::decryptToBytes(ciphertext, privateKey)` |
| **C#** | `SM2Util.decrypt(encryptedTextHexBytes, privateKeyBytes)` → byte[] (需先 hex→byte) |
| **Java** | `SM2Util.decryptToBytes(ciphertext, privateKey)` |
| **Python** | `SM2Util.decrypt_from_hex(cipher_hex, private_key)` |
| **JavaScript** | `SM2Util.decryptToBytesFromString(cipherHex, privateKey)` |
| **Go** | `Decrypt(string(ciphertext), privKey)` 结合 `ConvertStringToBytes` |
| **Rust** | `sm2::decrypt_with_private_pem_hex(private_pem, ciphertext_hex)` |

---

### SM2_decrypt_base64_to_bytes

> 输入 Base64 编码密文，私钥为 HEX/Base64 字符串，输出明文字节数组。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_decrypt_bytes(ciphertext_b64, private_key, &plaintext, &plaintext_len)` |
| **C++** | `SM2Util::decryptToBytes(ciphertext, privateKey)` |
| **Java** | `SM2Util.decryptToBytes(ciphertext, privateKey)` |
| **Python** | `SM2Util.decrypt_from_base64(cipher_b64, private_key)` |
| **JavaScript** | `SM2Util.decryptToBytesFromString(cipherBase64, privateKey)` |
| **Rust** | `sm2::decrypt_with_private_pem_base64(private_pem, ciphertext_b64)` |

---

### SM2_decrypt_bytes_to_bytes

> 输入密文字节数组，私钥为字节数组（DER），输出明文字节数组。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_decrypt_bytes(ciphertext_hex, private_key, &plaintext, &plaintext_len)` (传入 HEX 字符串，内部解码) |
| **C++** | `SM2Util::decryptToBytes(ciphertext_bytes, privateKey_bytes)` |
| **C#** | `SM2Util.decrypt(encryptedTextBytes, privateKeyBytes)` |
| **Java** | `SM2Util.decryptToBytes(encryptedTextBytes, privateKeyBytes)` |
| **JavaScript** | `SM2Util.decryptToBytes(cipherBytes, privateKey)` |
| **Go** | `DecryptBytes(ciphertext, privDer)` |
| **Rust** | `sm2::decrypt_with_private_pem(private_pem, ciphertext)` |

---

## 4. SM2 签名

### SM2_sign_utf8_to_hex

> 输入 UTF-8 字符串，私钥为 HEX/Base64 字符串（自动检测），输出 HEX 编码的 DER 签名。

| 语言 | 调用方式 | 参数说明 |
|------|----------|----------|
| **C** | `crossmool_sm2_sign(content, NULL, private_key, &signature_hex)` | `content`: 待签名字符串, `NULL`: UTF-8 |
| **C++** | `SM2Util::sign(content, privateKey)` 或 `SM2Util::signToHex(content, privateKey)` | 默认 HEX 输出 |
| **C#** | `SM2Util.signToHex(message, privateKeyString)` | |
| **Java** | `SM2Util.sign(content, privateKey)` 或 `SM2Util.signToHex(content, privateKey)` | 默认 HEX 输出 |
| **Python** | `SM2Util.sign(content, private_key)` | 默认 HEX 输出 |
| **JavaScript** | `SM2Util.sign(content, privateKey)` 或 `SM2Util.signToHex(content, privateKey)` | 默认 HEX 输出 |
| **Go** | `Sign(content, signPrivateKey, false)` 或 `SignDefault(content, signPrivateKey)` | `false`: HEX |
| **Rust** | `sm2::sign_with_private_pem(msg, private_pkcs8_pem)` → Vec\<u8\>（需手动 hex 编码） |

**调用示例**:

```c
// C
char* sig = NULL;
crossmool_sm2_sign("Hello", NULL, private_key, &sig);
free(sig);
```

```cpp
// C++
std::string sig = SM2Util::sign("Hello", privateKey);
```

```csharp
// C#
string sig = SM2Util.signToHex("Hello", privateKeyHex);
```

```java
// Java
String sig = SM2Util.sign("Hello", privateKey);
```

```python
# Python
sig = SM2Util.sign("Hello", priv_hex)
```

```typescript
// JavaScript / TypeScript
const sig = SM2Util.sign('Hello', privateKeyHex);
```

```go
// Go
sig, _ := crossmool.SignDefault("Hello", privHex)
```

```rust
// Rust
let sig = sm2::sign_with_private_pem(b"Hello", &keypair.private_key_pem).unwrap();
let sig_hex = hex::encode(&sig);
```

---

### SM2_sign_utf8_to_base64

> 输入 UTF-8 字符串，私钥为 HEX/Base64 字符串（自动检测），输出 Base64 编码的 DER 签名。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_sign_to_base64(content, content_len, charset, private_key, &signature_b64)` |
| **C++** | `SM2Util::sign(content, privateKey, true)` 或 `SM2Util::signToBase64(content, privateKey)` |
| **C#** | `SM2Util.signToBase64(message, privateKeyString)` |
| **Java** | `SM2Util.sign(content, privateKey, true)` 或 `SM2Util.signToBase64(content, privateKey)` |
| **Python** | `SM2Util.sign(content, private_key, to_base64=True)` 或 `SM2Util.sign_to_base64(content.encode('utf-8'), private_key)` |
| **JavaScript** | `SM2Util.sign(content, privateKey, true)` 或 `SM2Util.signToBase64(content, privateKey)` |
| **Go** | `Sign(content, signPrivateKey, true)` |
| **Rust** | (需手动 base64 编码) |

---

### SM2_sign_bytes_to_hex

> 输入字节数组，私钥为 HEX/Base64 字符串，输出 HEX 编码的 DER 签名。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_sign_to_hex(content, content_len, charset, private_key, &signature_hex)` |
| **C++** | `SM2Util::signToHex(content, privateKey)` |
| **Java** | `SM2Util.signToHex(content, privateKey)` |
| **Python** | `SM2Util.sign_to_hex(content, private_key)` → content: bytes |
| **JavaScript** | `SM2Util.signToHex(content, privateKey)` → content: string \| Uint8Array |
| **Go** | `SignDefault(string(content), signPrivateKey)` |
| **Rust** | `sm2::sign_with_private_pem(msg, private_pkcs8_pem)` + `hex::encode()` |

---

### SM2_sign_bytes_to_base64

> 输入字节数组，私钥为 HEX/Base64 字符串，输出 Base64 编码的 DER 签名。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_sign_to_base64(content, content_len, charset, private_key, &signature_b64)` |
| **C++** | `SM2Util::signToBase64(content, privateKey)` |
| **Java** | `SM2Util.signToBase64(content, privateKey)` |
| **Python** | `SM2Util.sign_to_base64(content, private_key)` |
| **JavaScript** | `SM2Util.signToBase64(content, privateKey)` |
| **Go** | `Sign(string(content), signPrivateKey, true)` |

---

### SM2_sign_bytes_to_bytes

> 输入字节数组，私钥为字节数组（DER），输出原始签名字节数组。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_sign_bytes(content, content_len, private_key, &signature, &signature_len)` |
| **C++** | `SM2Util::sign(content_bytes, privateKey_bytes)` |
| **C#** | `SM2Util.sign(messageBytes, privateKeyBytes)` |
| **Java** | `SM2Util.sign(contentBytes, privateKeyBytes)` |
| **Python** | `SM2Util.sign_to_der(content, private_key)` |
| **JavaScript** | `SM2Util.signToBytes(content, privateKey)` → Uint8Array |
| **Go** | `SignBytes(content, privDer)` |
| **Rust** | `sm2::sign_bytes(msg, private_pkcs8_der)` |

---

## 5. SM2 验签

### SM2_verify

> 验证签名。输入为待验证数据（UTF-8 字符串或字节数组）、签名（HEX 或 Base64，自动检测）、公钥（HEX 或 Base64，自动检测）。

#### SM2_verify（字符串输入）

| 语言 | 调用方式 | 签名格式 |
|------|----------|----------|
| **C** | `crossmool_sm2_verify(content, NULL, signature, public_key)` → int (1=通过, 0=失败, 负=错误) | 自动检测 HEX/Base64 |
| **C++** | `SM2Util::verify(content, publicKey, signature, "UTF-8")` → bool | 自动检测 HEX/Base64 |
| **C#** | `SM2Util.verify(message, signatureString, publicKeyString)` → bool | 自动检测 HEX/Base64 |
| **Java** | `SM2Util.verify(content, publicKey, signature)` → boolean | 自动检测 HEX/Base64 |
| **Python** | `SM2Util.verify_str(content, public_key, signature)` → bool | 自动检测 |
| **JavaScript** | `SM2Util.verify(content, publicKey, signatureHexOrBase64)` → boolean | 自动检测 HEX/Base64 |
| **Go** | `Verify(content, publicKey, signature)` → (bool, error) | 自动检测 HEX/Base64 |
| **Rust** | `sm2::verify_with_public_pem(msg, signature, public_pem)` → Result\<bool, String\> | 需字节数组输入 |

#### SM2_verify_bytes（字节输入）

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_verify_bytes(content, content_len, signature, public_key)` |
| **C++** | `SM2Util::verify(content_bytes, signature_bytes, publicKey_bytes)` |
| **C#** | `SM2Util.verify(messageBytes, signatureBytes, publicKeyBytes)` |
| **Java** | `SM2Util.verify(contentBytes, signatureBytes, publicKeyBytes)` |
| **Python** | `SM2Util.verify(content_bytes, public_key, signature_bytes)` |
| **JavaScript** | `SM2Util.verify(content, publicKey, signatureHexOrBase64)` → content: Uint8Array |
| **Go** | `VerifyBytes(content, signature, pubDer)` |
| **Rust** | `sm2::verify_bytes(msg, signature, public_x509_der)` |

**调用示例**:

```c
// C
int ok = crossmool_sm2_verify("Hello", NULL, signature_hex, public_key);
printf("Verify: %s\n", ok == 1 ? "OK" : "FAIL");
```

```cpp
// C++
bool ok = SM2Util::verify("Hello", publicKey, signature);
```

```csharp
// C#
bool ok = SM2Util.verify("Hello", signature, publicKeyHex);
```

```java
// Java
boolean ok = SM2Util.verify("Hello", publicKey, signature);
```

```python
# Python
ok = SM2Util.verify_str("Hello", pub_hex, sig_hex)
```

```typescript
// JavaScript / TypeScript
const ok = SM2Util.verify('Hello', publicKeyHex, sigHex);
```

```go
// Go
ok, _ := crossmool.Verify("Hello", pubHex, sigHex)
```

```rust
// Rust
let ok = sm2::verify_with_public_pem(b"Hello", &sig_bytes, &keypair.public_key_pem).unwrap();
```

---

## 6. SM2 加密并签名

### SM2_encrypt_sign_utf8_to_hex

> 对 UTF-8 明文同时加密和签名，输出 HEX 格式的密文和签名。使用不同的密钥对：加密用对方的公钥，签名用自己的私钥。

| 语言 | 调用方式 | 返回值 |
|------|----------|--------|
| **C** | `crossmool_sm2_encrypt_sign(content, charset, enc_public_key, sign_private_key, &result)` | `result->ciphertext_hex` / `result->signature_hex` |
| **C++** | `SM2Util::encryptSign(content, encPublicKey, signPrivateKey)` | `CiphertextSignaturePair{ ciphertext, signature }`（默认 HEX） |
| **C#** | `SM2Util.encryptSign(message, publicKeyString, privateKeyString, false)` | `(string ciphertext, string signature)` 元组 |
| **Java** | `SM2Util.encryptSign(content, encPublicKey, signPrivateKey)` | `CiphertextSignaturePair`（`.getCiphertext()` / `.getSignature()`） |
| **JavaScript** | `SM2Util.encryptSign(content, encPublicKey, signPrivateKey)` | `CiphertextSignaturePair{ ciphertext, signature }`（默认 HEX） |
| **Go** | `EncryptSignDefault(content, encPublicKey, signPrivateKey)` | `*CiphertextSignaturePair` |
| **Python** | 不直接提供（可手动调用加密+签名组合） | — |
| **Rust** | 不直接提供（可手动调用加密+签名组合） | — |

---

### SM2_encrypt_sign_utf8_to_base64

> 同上的操作，但输出 Base64 格式的密文和签名。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm2_encrypt_sign_ex(content, content_len, charset, enc_public_key, sign_private_key, 1, &result)` |
| **C++** | `SM2Util::encryptSign(content, encPublicKey, signPrivateKey, true)` |
| **C#** | `SM2Util.encryptSign(message, publicKeyString, privateKeyString, true)` |
| **Java** | `SM2Util.encryptSign(content, encPublicKey, signPrivateKey, true)` |
| **JavaScript** | `SM2Util.encryptSign(content, encPublicKey, signPrivateKey, true)` |
| **Go** | `EncryptSign(content, encPublicKey, signPrivateKey, true)` |

---

### SM2_encrypt_sign_utf8_to_hex (HEX 密钥显式调用)

> 明确使用 HEX 格式密钥调用的加密签名变体。

| 语言 | 调用方式 |
|------|----------|
| **Java** | `SM2Util.encryptSignWithHexKeys(content, encPublicKey, signPrivateKey)` |
| **Go** | `EncryptSignWithHexKeys(content, encPublicKey, signPrivateKey)` |

---

### SM2_encrypt_sign_utf8_to_hex (Base64 密钥显式调用)

> 明确使用 Base64 格式密钥调用的加密签名变体。

| 语言 | 调用方式 |
|------|----------|
| **Java** | `SM2Util.encryptSignWithBase64Keys(content, encPublicKey, signPrivateKey)` |
| **Go** | `EncryptSignWithBase64Keys(content, encPublicKey, signPrivateKey)` |

---

### SM2_encrypt_sign_utf8_to_hex (同格式密钥)

> 使用相同格式密钥自动匹配调用的加密签名变体。

| 语言 | 调用方式 |
|------|----------|
| **Java** | `SM2Util.encryptSignWithSameFormatKeys(content, encPublicKey, signPrivateKey)` |
| **JavaScript** | `SM2Util.encryptSignWithSameFormatKeys(content, encPublicKey, signPrivateKey)` |
| **Go** | `EncryptSignWithSameFormatKeys(content, encPublicKey, signPrivateKey)` |

**调用示例**:

```java
// Java
CiphertextSignaturePair pair = SM2Util.encryptSign("Hello", encPubKey, signPrivKey);
```

```typescript
// JavaScript
const pair = SM2Util.encryptSign('Hello', encPubKey, signPrivKey);
```

```go
// Go
pair, _ := crossmool.EncryptSignDefault("Hello", encPubHex, signPrivHex)
```

---

## 7. SM2 验签并解密

### SM2_verify_decrypt_hex_to_utf8

> 首先验签，验证通过后再解密，输出 UTF-8 明文。输入密文和签名均为 HEX 格式。

| 语言 | 调用方式 | 返回值 |
|------|----------|--------|
| **C** | `crossmool_sm2_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key, dec_private_key, NULL, &plaintext)` | `plaintext`: 明文（验签失败返回错误码） |
| **C++** | `SM2Util::verifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)` | string（验签失败抛异常） |
| **C#** | `SM2Util.verifyDecrypt(ciphertextString, signatureString, signPublicKeyString, decPrivateKeyString)` | string |
| **Java** | `SM2Util.verifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)` | String |
| **JavaScript** | `SM2Util.verifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)` | string |
| **Go** | `VerifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)` | (string, error) |
| **Python** | 不直接提供 | — |
| **Rust** | 不直接提供 | — |

---

### SM2_verify_decrypt_base64_to_utf8

> 同上，但密文和签名为 Base64 格式。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM2Util::verifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)` (自动检测) |
| **C#** | `SM2Util.verifyDecrypt(ciphertextString, signatureString, signPublicKeyString, decPrivateKeyString)` (自动检测) |
| **Java** | `SM2Util.verifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)` (自动检测) |
| **JavaScript** | `SM2Util.verifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)` (自动检测) |
| **Go** | `VerifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)` (自动检测) |

---

### SM2_verify_decrypt_pair

> 使用 `CiphertextSignaturePair` 结构体进行验签解密。

| 语言 | 调用方式 |
|------|----------|
| **Java** | `SM2Util.verifyDecrypt(cipherSigPair, signPublicKey, decPrivateKey)` |
| **JavaScript** | `SM2Util.verifyDecryptPair(pair, signPublicKey, decPrivateKey)` |
| **Go** | `VerifyDecryptPair(pair, signPublicKey, decPrivateKey)` |

**调用示例**:

```java
// Java
String plain = SM2Util.verifyDecrypt(ctHex, sigHex, signPubKey, decPrivKey);
```

```typescript
// JavaScript
const plain = SM2Util.verifyDecrypt(ctHex, sigHex, signPubKey, decPrivKey);
```

```go
// Go
plain, _ := crossmool.VerifyDecrypt(ctHex, sigHex, signPubHex, decPrivHex)
```

---

## 8. SM3 杂凑

### SM3_digest_utf8_to_hex

> 对 UTF-8 字符串做 SM3 杂凑，输出 HEX 格式（64 字符）。

| 语言 | 调用方式 | 参数说明 |
|------|----------|----------|
| **C** | `crossmool_sm3_digest_str(str, NULL, &digest_hex)` | `str`: 输入字符串, `NULL`: UTF-8 |
| **C++** | `SM3Util::digestToStr(input)` | 默认 HEX 输出 |
| **C#** | `SM3Util.digest(input)` 或 `SM3Util.digestToStr(Encoding.UTF8.GetBytes(input))` | 默认 HEX 输出 |
| **Java** | `SM3Util.digestToStr(input)` | 默认 HEX 输出 |
| **Python** | `SM3Util.digest_str(input_str)` | 默认 HEX 输出 |
| **JavaScript** | `SM3Util.digest(input)` 或 `SM3Util.digestToHex(input)` | `input`: string \| Uint8Array |
| **Go** | `DigestToStr(input, false)` | `false`: HEX 输出 |
| **Rust** | `sm3::digest_str_default(input)` | 默认 HEX 输出 |

**调用示例**:

```c
// C
char* hash = NULL;
crossmool_sm3_digest_str("Hello, SM3!", NULL, &hash);
free(hash);
```

```cpp
// C++
std::string hash = SM3Util::digestToStr("Hello, SM3!");
```

```csharp
// C#
string hash = SM3Util.digest("Hello, SM3!");
```

```java
// Java
String hash = SM3Util.digestToStr("Hello, SM3!");
```

```python
# Python
hash = SM3Util.digest_str("Hello, SM3!")
```

```typescript
// JavaScript / TypeScript
const hash = SM3Util.digest('Hello, SM3!');
```

```go
// Go
hash := crossmool.DigestToStr("Hello, SM3!", false)
```

```rust
// Rust
let hash = sm3::digest_str_default("Hello, SM3!");
```

---

### SM3_digest_utf8_to_base64

> 对 UTF-8 字符串做 SM3 杂凑，输出 Base64 格式。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm3_digest_str_to_base64(str, NULL, &digest_b64)` |
| **C++** | `SM3Util::digestToStr(input, true)` |
| **C#** | `SM3Util.digest(input, true)` 或 `SM3Util.digestBase64(input)` |
| **Java** | `SM3Util.digestToStr(input, true)` |
| **Python** | `SM3Util.digest_str(input_str, to_base64=True)` |
| **JavaScript** | `SM3Util.digest(input, true)` 或 `SM3Util.digestToBase64(input)` |
| **Go** | `DigestToStr(input, true)` |
| **Rust** | `sm3::digest_str(input, true)` |

---

### SM3_digest_bytes_to_hex

> 对字节数组做 SM3 杂凑，输出 HEX 格式。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm3_digest_to_hex(data, data_len, &digest_hex)` |
| **C++** | `SM3Util::digestToHex(data)` |
| **C#** | `SM3Util.digestToStr(data, false)` |
| **Java** | `SM3Util.digestToHex(data)` 或 `SM3Util.digestToStr(data)` |
| **Python** | `SM3Util.digest_to_hex(data)` |
| **JavaScript** | `SM3Util.digestToHex(data)` |
| **Go** | `DigestHex(data)` |
| **Rust** | `sm3::digest_hex(data)` |

---

### SM3_digest_bytes_to_base64

> 对字节数组做 SM3 杂凑，输出 Base64 格式。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm3_digest_to_base64(data, data_len, &digest_b64)` |
| **C++** | `SM3Util::digestToStr(data, true)` |
| **C#** | `SM3Util.digestToStr(data, true)` |
| **Python** | `SM3Util.digest_to_base64(data)` |
| **JavaScript** | `SM3Util.digestToBase64(data)` |
| **Go** | `DigestBase64(data)` |
| **Rust** | `sm3::digest_base64(data)` |

---

### SM3_digest_bytes_to_bytes

> 对字节数组做 SM3 杂凑，输出 32 字节原始杂凑值。

| 语言 | 调用方式 | 输出类型 |
|------|----------|----------|
| **C** | `crossmool_sm3_digest(data, data_len, digest)` | `unsigned char[32]` |
| **C++** | `SM3Util::digest(data)` | `vector<unsigned char>` |
| **C#** | `SM3Util.digest(data)` | `byte[]` |
| **Java** | `SM3Util.digest(data)` | `byte[]` |
| **Python** | `SM3Util.digest(data)` | `bytes` |
| **JavaScript** | `SM3Util.digestToBytes(data)` | `Uint8Array` |
| **Go** | `Digest(data)` | `[]byte` |
| **Rust** | `sm3::digest_bytes(data)` | `Vec<u8>` |

---

## 9. SM3 HMAC 密钥生成

### SM3_generate_hmac_key_bytes

> 生成随机 HMAC 密钥（推荐长度 32 字节）。

| 语言 | 调用方式 | 默认长度 |
|------|----------|----------|
| **C** | `crossmool_sm3_generate_hmac_key(key_length, &key)` | 需显式指定 |
| **C++** | `SM3Util::generateHmacKey(keyLengthInBytes)` | 32 |
| **C#** | `SM3Util.generateHmacKey(keyLengthInBytes)` | 32 |
| **Java** | `SM3Util.generateHmacKey(keyLengthInBytes)` 或 `SM3Util.generateHmacKey()` | 32 |
| **Python** | `SM3Util.generate_hmac_key(key_length)` | 32 |
| **JavaScript** | `SM3Util.generateHmacKeyBytes(keyLength)` | 32 |
| **Go** | `GenerateHmacKey(length)` | 需显式指定 |
| **Rust** | `sm3::generate_hmac_key(length)` | 需显式指定 |

---

### SM3_generate_hmac_key_hex

> 生成随机 HMAC 密钥，输出 HEX 字符串。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM3Util::generateHmacKeyToStr(keyLengthInBytes, false)` |
| **C#** | `SM3Util.generateHmacKeyToStr(keyLengthInBytes, false)` |
| **Java** | `SM3Util.generateHmacKeyToStr(keyLengthInBytes, false)` 或 `SM3Util.generateHmacKeyToStr(keyLengthInBytes)` |
| **Python** | `SM3Util.generate_hmac_key_to_str(key_length, False)` |
| **JavaScript** | `SM3Util.generateHmacKeyToStr(keyLength, false)` 或 `SM3Util.generateHmacKeyHex(keyLength)` |
| **Go** | `GenerateHmacKeyToStr(length, false)` |
| **Rust** | `sm3::generate_hmac_key_to_str(length, false)` 或 `sm3::generate_hmac_key_str(false)` |

---

### SM3_generate_hmac_key_base64

> 生成随机 HMAC 密钥，输出 Base64 字符串。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM3Util::generateHmacKeyToStr(keyLengthInBytes, true)` |
| **C#** | `SM3Util.generateHmacKeyToStr(keyLengthInBytes, true)` |
| **Java** | `SM3Util.generateHmacKeyToStr(keyLengthInBytes, true)` |
| **Python** | `SM3Util.generate_hmac_key_to_str(key_length, True)` |
| **JavaScript** | `SM3Util.generateHmacKeyToStr(keyLength, true)` 或 `SM3Util.generateHmacKeyBase64(keyLength)` |
| **Go** | `GenerateHmacKeyToStr(length, true)` |
| **Rust** | `sm3::generate_hmac_key_to_str(length, true)` 或 `sm3::generate_hmac_key_str(true)` |

---

## 10. SM3 HMAC 计算

### SM3_hmac_bytes_to_bytes

> 使用字节数组密钥和字节数组数据计算 HMAC-SM3，输出原始 32 字节。

| 语言 | 调用方式 | 输出类型 |
|------|----------|----------|
| **C** | `crossmool_sm3_hmac(key, key_len, data, data_len, mac)` | `unsigned char[32]` |
| **C++** | `SM3Util::hmac(key_bytes, data_bytes)` | `vector<unsigned char>` |
| **C#** | `SM3Util.hmac(keyBytes, dataBytes)` | `byte[]` |
| **Java** | `SM3Util.hmac(keyBytes, dataBytes)` | `byte[]` |
| **Python** | `SM3Util.hmac(key, data)` → bytes | `bytes` |
| **JavaScript** | `SM3Util.hmacBytes(key, data)` | `Uint8Array` |
| **Go** | `HMAC(key, data)` | `[]byte` |
| **Rust** | `sm3::hmac_bytes(key, data)` | `Vec<u8>` |

---

### SM3_hmac_utf8_to_hex

> 使用 HEX/Base64 格式的密钥字符串和 UTF-8 数据字符串计算 HMAC-SM3，输出 HEX 格式。

| 语言 | 调用方式 | 参数说明 |
|------|----------|----------|
| **C** | `crossmool_sm3_hmac_hex(key_hex, data, data_len, &hmac_hex)` | `key_hex`: HEX 字符串, `data`: 字节数组 |
| **C++** | `SM3Util::hmacToStr(key_str, data_str, false)` | 默认 HEX 输出 |
| **C#** | `SM3Util.hmacToStr(key, data, false)` | 默认 HEX 输出 |
| **Java** | `SM3Util.hmacToStr(key, data)` 或 `SM3Util.hmacToStr(key, data, false)` | 默认 HEX 输出 |
| **Python** | `SM3Util.hmac_str(key_str, data_str)` | 默认 HEX 输出 |
| **JavaScript** | `SM3Util.hmac(key, data)` 或 `SM3Util.hmacToHex(key, data)` | 默认 HEX 输出 |
| **Go** | `HMACToStr(key, data, false)` | `false`: HEX |
| **Rust** | `sm3::hmac_str_default(key, data)` | 默认 HEX 输出 |

**调用示例**:

```cpp
// C++
std::string mac = SM3Util::hmacToStr("my-hmac-key", "Hello, HMAC-SM3!");
```

```java
// Java
String mac = SM3Util.hmacToStr("my-hmac-key", "Hello, HMAC-SM3!");
```

```python
# Python
mac = SM3Util.hmac_str("my-hmac-key", "Hello, HMAC-SM3!")
```

```typescript
// JavaScript / TypeScript
const mac = SM3Util.hmac('my-hmac-key', 'Hello, HMAC-SM3!');
```

```go
// Go
mac, _ := crossmool.HMACToStr("my-hmac-key", "Hello, HMAC-SM3!", false)
```

```rust
// Rust
let mac = sm3::hmac_str_default("my-hmac-key", "Hello, HMAC-SM3!").unwrap();
```

---

### SM3_hmac_utf8_to_base64

> 使用字符串密钥和 UTF-8 数据计算 HMAC-SM3，输出 Base64 格式。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm3_hmac_to_base64(key, data, &mac_b64)` |
| **C++** | `SM3Util::hmacToStr(key_str, data_str, true)` |
| **C#** | `SM3Util.hmacToStr(key, data, true)` |
| **Java** | `SM3Util.hmacToStr(key, data, true)` |
| **Python** | `SM3Util.hmac_str(key_str, data_str, to_base64=True)` |
| **JavaScript** | `SM3Util.hmac(key, data, true)` 或 `SM3Util.hmacToBase64(key, data)` |
| **Go** | `HMACToStr(key, data, true)` |
| **Rust** | `sm3::hmac_str(key, data, true)` |

---

### SM3_hmac_bytes_to_hex

> 使用字节数组密钥和字节数组数据计算 HMAC-SM3，输出 HEX 格式。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM3Util::hmacToStr(key_bytes, data_bytes, false)` |
| **C#** | `SM3Util.hmacToStr(keyBytes, dataBytes, false)` |
| **Java** | `SM3Util.hmacToStr(keyBytes, dataBytes)` 或 `SM3Util.hmacToStr(keyBytes, dataBytes, false)` |
| **Python** | `SM3Util.hmac_to_hex(key, data)` 或 `SM3Util.hmac_to_str(key, data, False)` |
| **JavaScript** | `SM3Util.hmacToHex(key, data)` |
| **Go** | `HMACToStr(EncodeHex(key), EncodeHex(data), false)` (需先转 hex) |
| **Rust** | `sm3::hmac_hex(key, data)` |

---

### SM3_hmac_bytes_to_base64

> 使用字节数组密钥和字节数组数据计算 HMAC-SM3，输出 Base64 格式。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM3Util::hmacToStr(key_bytes, data_bytes, true)` |
| **C#** | `SM3Util.hmacToStr(keyBytes, dataBytes, true)` |
| **Python** | `SM3Util.hmac_to_base64(key, data)` 或 `SM3Util.hmac_to_str(key, data, True)` |
| **JavaScript** | `SM3Util.hmacToBase64(key, data)` |
| **Go** | `HMACToStr(EncodeHex(key), EncodeHex(data), true)` (需先转 hex) |
| **Rust** | `sm3::hmac_base64(key, data)` |

---

## 11. SM3 HMAC 验证

### SM3_hmac_verify

> 验证 HMAC-SM3 值。输入密钥、数据与接收到的 HMAC 值，返回是否匹配。

| 语言 | 调用方式 | 返回值 |
|------|----------|--------|
| **C** | `crossmool_sm3_hmac_verify(key, charset, data, data_charset, received_mac)` | int (1=匹配, 0=不匹配, 负=错误) |
| **C++** | `SM3Util::hmacVerify(key, data, receivedHmac)` | bool |
| **JavaScript** | `SM3Util.hmacVerify(key, data, receivedHmac)` | boolean |
| **Java** | `SM3Util.hmacVerify(key, data, receivedHmac)` | boolean |

> 注意：C#、Python、Go、Rust 可直接计算 HMAC 后字符串比较，未单独提供 verify 方法。

---

## 12. SM4 密钥管理

### SM4_generate_key_bytes

> 生成 16 字节（128 bits）SM4 随机密钥。

| 语言 | 调用方式 | 输出类型 |
|------|----------|----------|
| **C** | `crossmool_sm4_generate_key(key)` | `unsigned char[16]` |
| **C++** | `SM4Util::generateKey()` | `vector<unsigned char>` |
| **C#** | `SM4Util.GenerateKey()` | `byte[]` |
| **Java** | `SM4Util.generateKey()` | `byte[]` |
| **Python** | `SM4Util.generate_key()` | `bytes` |
| **JavaScript** | `SM4Util.generateKeyBytes()` | `Uint8Array` |
| **Go** | `GenerateKey()` | `([]byte, error)` |
| **Rust** | `sm4::generate_key()` | `Vec<u8>` |

---

### SM4_generate_key_hex

> 生成 SM4 随机密钥，输出 HEX 字符串（32 字符）。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm4_generate_key_hex(&key_hex)` |
| **C++** | `SM4Util::generateKeyAsHex()` |
| **C#** | `SM4Util.GenerateKeyAsHex()` |
| **Java** | `SM4Util.generateKeyAsHex()` |
| **Python** | `SM4Util.generate_key_hex()` |
| **JavaScript** | `SM4Util.generateKeyHex()` |
| **Go** | `GenerateKey()` + `EncodeHex(key)` |
| **Rust** | `sm4::generate_key()` + `encoding::to_hex(&key)` |

**调用示例**:

```java
// Java
String hexKey = SM4Util.generateKeyAsHex();
```

```python
# Python
hex_key = SM4Util.generate_key_hex()
```

```typescript
// JavaScript
const hexKey = SM4Util.generateKeyHex();
```

---

### SM4_generate_key_base64

> 生成 SM4 随机密钥，输出 Base64 字符串。

| 语言 | 调用方式 |
|------|----------|
| **Java** | `SM4Util.generateKeyAsBase64()` |
| **JavaScript** | `SM4Util.generateKeyBase64()` |
| **Go** | `GenerateKey()` + `EncodeBase64(key)` |
| **Rust** | `sm4::generate_key()` + `encoding::to_base64(&key)` |

---

### SM4_parse_hex_key

> 将 HEX 格式的 SM4 密钥字符串解析为字节数组。

| 语言 | 调用方式 | 输出类型 |
|------|----------|----------|
| **C** | `crossmool_sm4_parse_hex_key(hex_key, key)` | `unsigned char[16]` |
| **C++** | `SM4Util::parseHexKey(hexKey)` | `vector<unsigned char>` |
| **C#** | `SM4Util.ParseHexKey(hexKey)` | `byte[]` |
| **Java** | `SM4Util.parseHexKey(hexKey)` | `byte[]` |
| **Python** | `SM4Util.parse_hex_key(hex_key)` | `bytes` |
| **JavaScript** | `SM4Util.parseHexKey(hexKey)` | `Uint8Array` |
| **Go** | `DecodeHexString(s)` | `([]byte, error)` |
| **Rust** | `encoding::from_hex(hexstr)` | `Result<Vec<u8>, ...>` |

---

## 13. SM4 GCM 加密

### SM4_gcm_encrypt_bytes_to_hex

> 对字节数组明文做 SM4 GCM 加密，输出 HEX 格式密文。输出格式为 `HEX(IV[12] + 密文 + Tag[16])`。

| 语言 | 调用方式 | 参数说明 |
|------|----------|----------|
| **C** | `crossmool_sm4_encrypt_gcm_hex(key, plaintext, plaintext_len, &ciphertext_hex)` | `key`: 16 字节 |
| **C++** | `SM4Util::encryptGcm(key, plaintext, false)` | `false`: HEX 输出 |
| **C#** | `SM4Util.EncryptGcm(key, plaintext, false)` 或 `SM4Util.EncryptGcmHex(key, plaintext)` | `false`: HEX 输出 |
| **Java** | `SM4Util.encrypt(key, plaintext, false)` 或 `SM4Util.encryptToHex(key, plaintext)` | `false`: HEX |
| **Python** | `SM4Util.encrypt_gcm(key, plaintext, to_base64=False)` 或 `SM4Util.encrypt_gcm_hex(key, plaintext)` | |
| **JavaScript** | `SM4Util.encryptGcm(plaintext, key, iv, false)` 或 `SM4Util.encryptGcmHex(plaintext, key, iv)` | `false`: HEX |
| **Go** | `EncryptGcm(key, plain, false)` 或 `EncryptGcmHex(key, plain)` | `false`: HEX |
| **Rust** | `sm4::encrypt_gcm(key, plain, false)` 或 `sm4::encrypt_gcm_hex(key, plain)` | `false`: HEX |

**调用示例**:

```c
// C
unsigned char key[16];
crossmool_sm4_generate_key(key);
char* ct = NULL;
crossmool_sm4_encrypt_gcm_hex(key, (unsigned char*)"Hello", 5, &ct);
free(ct);
```

```cpp
// C++
auto key = SM4Util::generateKey();
std::string ct = SM4Util::encryptGcm(key, plaintext_vec, false);
```

```csharp
// C#
byte[] key = SM4Util.GenerateKey();
string ct = SM4Util.EncryptGcm(key, Encoding.UTF8.GetBytes("Hello"), false);
```

```java
// Java
byte[] key = SM4Util.generateKey();
String ct = SM4Util.encrypt(key, "Hello".getBytes(StandardCharsets.UTF_8), false);
```

```python
# Python
key = SM4Util.generate_key()
ct = SM4Util.encrypt_gcm(key, b"Hello", to_base64=False)
```

```typescript
// JavaScript / TypeScript
const key = SM4Util.generateKeyBytes();
const ct = SM4Util.encryptGcm(new TextEncoder().encode('Hello'), key, undefined, false);
```

```go
// Go
key, _ := crossmool.GenerateKey()
ct, _ := crossmool.EncryptGcm(key, []byte("Hello"), false)
```

```rust
// Rust
let key = sm4::generate_key();
let ct = sm4::encrypt_gcm(&key, b"Hello", false).unwrap();
```

---

### SM4_gcm_encrypt_bytes_to_base64

> 对字节数组明文做 SM4 GCM 加密，输出 Base64 格式密文。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm4_encrypt_gcm_base64(key, plaintext, plaintext_len, &ciphertext_b64)` |
| **C++** | `SM4Util::encryptGcm(key, plaintext, true)` |
| **C#** | `SM4Util.EncryptGcm(key, plaintext, true)` |
| **Java** | `SM4Util.encrypt(key, plaintext, true)` 或 `SM4Util.encryptToBase64(key, plaintext)` |
| **Python** | `SM4Util.encrypt_gcm(key, plaintext, to_base64=True)` |
| **JavaScript** | `SM4Util.encryptGcm(plaintext, key, iv, true)` 或 `SM4Util.encryptGcmBase64(plaintext, key, iv)` |
| **Go** | `EncryptGcm(key, plain, true)` |
| **Rust** | `sm4::encrypt_gcm(key, plain, true)` 或 `sm4::encrypt_gcm_base64(key, plain)` |

---

### SM4_gcm_encrypt_utf8_to_hex

> 对 UTF-8 字符串明文做 SM4 GCM 加密，输出 HEX 密文。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM4Util::encryptGcmString(key, plainText)` → Base64 输出 (需手动调用 HEX 版) |
| **C#** | `SM4Util.EncryptGcmString(key, plainText, false)` |
| **Java** | `SM4Util.encrypt(key, plaintext, false)` (重载 String, String) |
| **Python** | `SM4Util.encrypt_gcm_string(key, plain_text, to_base64=False)` |
| **JavaScript** | `SM4Util.encryptGcmString(plainText, key, undefined, false)` |
| **Go** | `EncryptGcm(key, []byte(plainText), false)` (需手动转换) |
| **Rust** | `sm4::encrypt_gcm_string(key, plain, false)` |

---

### SM4_gcm_encrypt_utf8_to_base64

> 对 UTF-8 字符串明文做 SM4 GCM 加密，输出 Base64 密文。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM4Util::encryptGcmString(key, plainText)` |
| **C#** | `SM4Util.EncryptGcmString(key, plainText, true)` |
| **Java** | `SM4Util.encrypt(key, plaintext, true)` (重载 String, String) |
| **Python** | `SM4Util.encrypt_gcm_string(key, plain_text, to_base64=True)` |
| **JavaScript** | `SM4Util.encryptGcmString(plainText, key, undefined, true)` |
| **Go** | `EncryptGcm(key, []byte(plainText), true)` (需手动转换) |
| **Rust** | `sm4::encrypt_gcm_string(key, plain, true)` |

---

## 14. SM4 GCM 解密

### SM4_gcm_decrypt_hex_to_bytes

> 从 HEX 格式密文解密，输出明文字节数组。密文格式为 `HEX(IV[12] + 密文 + Tag[16])`。

| 语言 | 调用方式 | 参数说明 |
|------|----------|----------|
| **C** | `crossmool_sm4_decrypt_gcm_hex(key, ciphertext_hex, &plaintext, &plaintext_len)` | `key`: 16 字节, `ciphertext_hex`: HEX 密文 |
| **C++** | `SM4Util::decryptGcm(key, ciphertextEncoded)` | 自动检测 HEX/Base64 |
| **C#** | `SM4Util.DecryptGcmFromHex(key, ciphertextHex)` | 明确指定 HEX |
| **Java** | `SM4Util.decryptToBytes(key, ciphertext)` | 自动检测 HEX/Base64 |
| **Python** | `SM4Util.decrypt_gcm_from_hex(key, hex_str)` 或 `SM4Util.decrypt_gcm(key, ciphertext_str)` | 自动检测 |
| **JavaScript** | `SM4Util.decryptGcmFromHex(ciphertextHex, key)` 或 `SM4Util.decryptGcm(ciphertextHexOrBase64, key)` | 自动检测 |
| **Go** | `DecryptGcm(key, encodedData)` 或 `DecryptGcmHex(key, hexStr)` | 自动检测 |
| **Rust** | `sm4::decrypt_gcm(key, encoded)` 或 `sm4::decrypt_gcm_from_hex(key, hex_str)` | 自动检测 |

**调用示例**:

```c
// C
unsigned char* pt = NULL;
size_t pt_len = 0;
crossmool_sm4_decrypt_gcm_hex(key, ciphertext_hex, &pt, &pt_len);
printf("%.*s\n", (int)pt_len, pt);
free(pt);
```

```cpp
// C++
auto pt = SM4Util::decryptGcm(key, ciphertext);
```

```csharp
// C#
byte[] pt = SM4Util.DecryptGcmFromHex(key, ctHex);
Console.WriteLine(Encoding.UTF8.GetString(pt));
```

```java
// Java
byte[] pt = SM4Util.decryptToBytes(key, ctHex);
```

```python
# Python
pt = SM4Util.decrypt_gcm(key, ct_hex)
```

```typescript
// JavaScript / TypeScript
const pt = SM4Util.decryptGcm(ctHex, key);
```

```go
// Go
pt, _ := crossmool.DecryptGcm(key, ctHex)
```

```rust
// Rust
let pt = sm4::decrypt_gcm(&key, &ct_hex).unwrap();
```

---

### SM4_gcm_decrypt_base64_to_bytes

> 从 Base64 格式密文解密，输出明文字节数组。

| 语言 | 调用方式 |
|------|----------|
| **C** | `crossmool_sm4_decrypt_gcm_base64(key, ciphertext_b64, &plaintext, &plaintext_len)` |
| **C++** | `SM4Util::decryptGcm(key, ciphertextEncoded)` (自动检测) |
| **C#** | `SM4Util.DecryptGcm(key, ciphertextEncoded)` (自动检测) |
| **Java** | `SM4Util.decryptToBytes(key, ciphertext)` (自动检测) |
| **Python** | `SM4Util.decrypt_gcm(key, ciphertext_str)` (自动检测) |
| **JavaScript** | `SM4Util.decryptGcm(ciphertextHexOrBase64, key)` (自动检测) |
| **Go** | `DecryptGcm(key, encodedData)` (自动检测) |
| **Rust** | `sm4::decrypt_gcm_base64(key, encoded)` |

---

### SM4_gcm_decrypt_hex_to_utf8

> 从 HEX 格式密文解密，输出 UTF-8 明文字符串。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM4Util::decryptGcmToString(key, ciphertextHex)` |
| **C#** | `SM4Util.DecryptGcmToString(key, ciphertextHex)` |
| **Java** | `SM4Util.decrypt(key, ciphertextHex)` (重载 byte[], String) |
| **Python** | `SM4Util.decrypt_gcm_to_string(key, ciphertext_str)` |
| **JavaScript** | `SM4Util.decryptGcmToString(ciphertextHexOrBase64, key)` |
| **Go** | `DecryptGcmToString(key, encodedData)` |
| **Rust** | `sm4::decrypt_gcm_to_string(key, encoded)` |

---

### SM4_gcm_decrypt_base64_to_utf8

> 从 Base64 格式密文解密，输出 UTF-8 明文字符串。

| 语言 | 调用方式 |
|------|----------|
| **C++** | `SM4Util::decryptGcmToString(key, ciphertextBase64)` (自动检测) |
| **C#** | `SM4Util.DecryptGcmToString(key, ciphertextEncoded)` (自动检测) |
| **Java** | `SM4Util.decrypt(key, ciphertextBase64)` (自动检测) |
| **Python** | `SM4Util.decrypt_gcm_to_string(key, ciphertext_str)` (自动检测) |
| **JavaScript** | `SM4Util.decryptGcmToString(ciphertextHexOrBase64, key)` (自动检测) |
| **Go** | `DecryptGcmToString(key, encodedData)` (自动检测) |
| **Rust** | `sm4::decrypt_gcm_base64_to_string(key, encoded)` |

---

## 15. 工具函数

### 15.1 HEX 编解码

| 函数 | C | C++ | C# | Java | Python | JavaScript | Go | Rust |
|------|---|-----|-----|------|--------|------------|-----|------|
| hex → bytes | `crossmool_hex_decode()` | `HexUtil::decodeHexStr()` | `EncodingUtils.FromHex()` | `HexUtil.decodeHexStr()` | `hex_to_bytes()` | `hexToBytes()` | `DecodeHexString()` | `from_hex()` |
| bytes → hex | `crossmool_hex_encode()` | `HexUtil::encodeHexStr()` | `EncodingUtils.ToHex()` | `HexUtil.encodeHexStr()` | `bytes_to_hex()` | `bytesToHex()` | `EncodeHex()` | `to_hex()` |
| 判断 hex 格式 | `crossmool_is_hex_string()` | `HexUtil::isHexString()` | `EncodingUtils.LooksLikeHex()` | `HexUtil.isHexString()` | `is_hex_string()` | `isHexString()` | `IsHexString()` | `is_hex()` |

### 15.2 Base64 编解码

| 函数 | C | C++ | C# | Java | Python | JavaScript | Go | Rust |
|------|---|-----|-----|------|--------|------------|-----|------|
| base64 → bytes | `crossmool_base64_decode()` | `Base64Util::decodeBase64Str()` | `EncodingUtils.FromBase64()` | `Base64Util.decodeBase64Str()` | `base64_to_bytes()` | `base64ToBytes()` | `DecodeBase64String()` | `from_base64()` |
| bytes → base64 | `crossmool_base64_encode()` | `Base64Util::encodeBase64Str()` | `EncodingUtils.ToBase64()` | `Base64Util.encodeBase64Str()` | `bytes_to_base64()` | `bytesToBase64()` | `EncodeBase64()` | `to_base64()` |
| 判断 base64 格式 | `crossmool_is_base64_string()` | `Base64Util::isBase64String()` | — | `Base64Util.isBase64String()` | `is_base64_string()` | `isBase64String()` | `IsBase64String()` | `is_base64()` |

### 15.3 UTF-8 编解码

| 函数 | C | C++ | C# | Python | JavaScript | Go | Rust |
|------|---|-----|-----|--------|------------|-----|------|
| utf8 → bytes | `crossmool_string_to_bytes()` | `StringUtil::stringToBytes()` | `EncodingUtils.Utf8GetBytes()` | `utf8_to_bytes()` | `utf8ToBytes()` | `[]byte(s)` (Go 原生) | `s.as_bytes()` (Rust 原生) |
| bytes → utf8 | `crossmool_bytes_to_string()` | `StringUtil::bytesToString()` | `EncodingUtils.Utf8GetString()` | `bytes_to_utf8()` | `bytesToUtf8()` | `string(b)` (Go 原生) | `String::from_utf8_lossy()` (Rust 原生) |

### 15.4 SM2 密钥格式转换

| 函数 | 说明 |
|------|------|
| `sm2PublicKeyToRawHex()` (JS) / `sm2_public_key_to_raw_hex()` (Python) | 将公钥（PEM/DER/HEX）转为 uncompressed HEX (`04+X+Y`) |
| `sm2PrivateKeyToRawHex()` (JS) / `sm2_private_key_to_raw_hex()` (Python) | 将私钥（PEM/DER/HEX）转为 32 字节 raw HEX |

---

## 附录: 快速查询表

以下表格汇总所有功能在各语言中的覆盖情况。✅ = 支持，⬜ = 不支持或需手动组合。

| 功能 | C | C++ | C# | Java | Python | JS | Go | Rust |
|------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| **SM2 密钥生成** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 加密 (utf8→hex)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 加密 (utf8→base64)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 加密 (bytes→bytes)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 解密 (hex→utf8)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 解密 (base64→utf8)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 签名 (utf8→hex)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 签名 (utf8→base64)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 验签** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM2 加密并签名** | ✅ | ✅ | ✅ | ✅ | ⬜ | ✅ | ✅ | ⬜ |
| **SM2 验签并解密** | ✅ | ✅ | ✅ | ✅ | ⬜ | ✅ | ✅ | ⬜ |
| **SM3 杂凑 (utf8→hex)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM3 杂凑 (utf8→base64)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM3 HMAC 密钥生成** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM3 HMAC 计算** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM3 HMAC 验证** | ✅ | ✅ | ⬜ | ✅ | ⬜ | ✅ | ⬜ | ⬜ |
| **SM4 密钥生成** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM4 GCM 加密 (bytes→hex)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM4 GCM 加密 (bytes→base64)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM4 GCM 解密 (hex→bytes)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM4 GCM 解密 (base64→bytes)** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM4 GCM 加密 (utf8→hex)** | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM4 GCM 加密 (utf8→base64)** | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM4 GCM 解密 (hex→utf8)** | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SM4 GCM 解密 (base64→utf8)** | ⬜ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

> **文档结束** — 各语言版本的详细 README 和示例代码请参见相应语言目录。
