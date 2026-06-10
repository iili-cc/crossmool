# Java-Rust SM 算法互操作性测试说明

## 概述

本目录包含 Java 和 Rust 语言之间 SM2/SM3/SM4 算法的互操作性测试用例。

## 测试文件

1. **run_java_rust_sm_interop_test.py** - 完整的互操作性测试脚本
   - 测试 SM2 加密/解密、签名/验签
   - 测试 SM3 哈希
   - 测试 SM4 GCM 加密/解密
   - 生成 JSON 格式的测试结果

2. **test_rust_sm4_java_compat.py** - 简化的 Rust 测试脚本
   - 测试 Rust SM2/SM3/SM4 基本功能
   - 验证 Rust 内部加解密一致性
   - 验证 Java-Rust SM4 互操作性

3. **Java-Rust-interop-test-report.md** - 测试报告

## 运行测试

### 前置条件

1. Java JDK 21+ 已安装
2. Rust 工具链已安装 (rustup, rustc, cargo)
3. Python 3.8+ 已安装

### 运行完整测试

```bash
python testcase/run_java_rust_sm_interop_test.py
```

### 运行简化测试

```bash
python testcase/test_rust_sm4_java_compat.py
```

### 运行 Rust 内置测试

```bash
cd rust/crossmool
cargo test --release
```

## 测试密钥

测试使用的密钥位于 `testcase/keys/rust/keys.json`

### SM2 密钥

- **加密公钥**: X.509 格式 (Hex 编码)
- **签名私钥**: PKCS#8 格式 (Hex 编码)

### SM4 测试向量

- **密钥**: `0123456789abcdeffedcba9876543210` (Hex)
- **IV**: `000102030405060708090a0b` (Hex)

## 编码格式支持

所有算法均支持 Hex 和 Base64 两种编码格式:

### SM2

- `encrypt_with_public_pem_hex()` - 加密输出 Hex
- `encrypt_with_public_pem_base64()` - 加密输出 Base64
- `decrypt_with_private_pem_hex()` - 从 Hex 解密
- `decrypt_with_private_pem_base64()` - 从 Base64 解密

### SM3

- `digest_hex()` - 哈希输出 Hex
- `digest_base64()` - 哈希输出 Base64
- `hmac_hex()` - HMAC 输出 Hex
- `hmac_base64()` - HMAC 输出 Base64

### SM4

- `encrypt_gcm_hex()` - 加密输出 Hex
- `encrypt_gcm_base64()` - 加密输出 Base64
- `decrypt_gcm()` - 自动检测 Hex/Base64 并解密
- `decrypt_gcm_from_hex()` - 从 Hex 解密
- `decrypt_gcm_base64()` - 从 Base64 解密

## Java SM4Util 更新

Java 的 `SM4Util.java` 已更新，现在支持 Hex 和 Base64 双编码格式:

### 新增方法

```java
// 生成密钥
String generateKeyAsHex()
String generateKeyAsBase64()
String generateKeyAsString(boolean toBase64)

// 解析密钥
byte[] parseKey(String key)  // 自动检测 Hex/Base64
byte[] parseHexKey(String hexKey)
byte[] parseBase64Key(String base64Key)

// 加密
String encrypt(String key, String plaintext, boolean toBase64)
String encrypt(String key, String plaintext)  // 默认 Hex

// 解密
String decrypt(String key, String ciphertext)  // 自动检测 Hex/Base64
```

### 使用示例

```java
// 生成密钥
String hexKey = SM4Util.generateKeyAsHex();
String base64Key = SM4Util.generateKeyAsBase64();

// 加密 (Hex 输出)
String ciphertextHex = SM4Util.encrypt(hexKey, "明文", false);

// 加密 (Base64 输出)
String ciphertextBase64 = SM4Util.encrypt(base64Key, "明文", true);

// 解密 (自动检测编码格式)
String plaintext1 = SM4Util.decrypt(hexKey, ciphertextHex);
String plaintext2 = SM4Util.decrypt(base64Key, ciphertextBase64);
```

## 预期结果

所有测试应该通过，Rust 实现应该能够:

1. 正确解密 Java 加密的数据
2. 正确验签 Java 签名的数据
3. 生成与 Java 兼容的加密和签名结果
4. SM3 哈希结果与 Java 完全一致
5. SM4 GCM 加密结果与 Java 完全一致 (使用相同密钥和 IV)

## 故障排除

### Rust 编译失败

确保 Rust 工具链是最新的:

```bash
rustup update
```

### 测试失败

1. 检查密钥文件是否正确
2. 检查测试数据文件是否存在
3. 查看错误输出以获取详细信息

### Java 编译失败

确保已安装 JDK 21+ 并设置 JAVA_HOME 环境变量

## 参考实现

- Java: `java/crossmool/src/main/java/cc/iili/tools/crossmool/tool/`
  - SM2Util.java
  - SM3Util.java
  - SM4Util.java

- Rust: `rust/crossmool/src/`
  - sm2.rs
  - sm3.rs
  - sm4.rs
  - encoding.rs

## 报告生成

测试完成后，结果将保存到:

- `testcase/results/java_rust_interop/` - JSON 格式测试结果
- `testcase/Java-Rust-interop-test-report.md` - Markdown 格式测试报告