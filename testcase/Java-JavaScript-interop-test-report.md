# Java-JavaScript SM2/SM3/SM4 互通性测试报告

## 测试概述

本报告测试了 Java 和 JavaScript 两种语言实现的 SM2、SM3、SM4 算法的互通性。

### 测试环境

- **Java 版本**: JDK 17.0.9+9
- **Node.js 版本**: 22.18.0 (npm 10.9.3)
- **JavaScript 库**: sm-crypto-v2 v1.15.1
- **Java 库**: Bouncy Castle
- **测试日期**: 2026 年 6 月 9 日

### 测试密钥

测试使用相同的密钥对进行 Java 和 JavaScript 之间的互通性验证：

- **加密公钥 (Hex)**: `3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4`
- **加密私钥 (Hex)**: `308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4`
- **签名公钥 (Hex)**: 同加密公钥
- **签名私钥 (Hex)**: 同加密私钥

### 测试用例

| ID | 名称 | 明文 |
|----|------|------|
| 1 | simple_text | Hello, Crossmool! |
| 2 | chinese_text | 跨语言互操作性测试 |
| 3 | mixed_content | Test 测试 123!@# |

---

## 测试结果摘要

| 算法 | 测试类型 | 通过 | 失败 | 通过率 |
|------|---------|------|------|--------|
| SM2 | 签名验签 (Hex) | 3 | 0 | 100% |
| SM3 | 哈希 | 3 | 0 | 100% |
| SM3 | HMAC | 2 | 1 | 67% |
| SM2 | 加密解密 (Hex) | 0 | 3 | 0% |
| SM2 | 加密签名组合 (Hex) | 0 | 3 | 0% |

---

## SM2 互通性测试

### SM2 签名验签互通性 (Hex 模式)

**测试方法**: 
1. Java 使用私钥对消息进行签名，生成 Hex 格式的签名
2. JavaScript 和 Java 分别使用公钥验证签名
3. 验证双方验签结果是否一致

**测试结果**:

| 测试用例 | Java 签名 | JS 验签 | Java 验签 | 状态 |
|---------|---------|-------|---------|------|
| 1 - simple_text | ✓ | ✓ | ✓ | ✅ 通过 |
| 2 - chinese_text | ✓ | ✓ | ✓ | ✅ 通过 |
| 3 - mixed_content | ✓ | ✓ | ✓ | ✅ 通过 |

**结论**: ✅ SM2 签名验签在 Hex 模式下完全互通。

### SM2 加密解密互通性 (Hex 模式)

**测试方法**: 
1. Java 使用公钥加密明文，生成 Hex 格式的密文
2. JavaScript 使用私钥解密 Java 生成的密文
3. 验证解密结果是否与原始明文一致

**测试结果**:

| 测试用例 | Java 加密 -> JS 解密 | Java 加密 -> Java 解密 | 状态 |
|---------|---------------------|----------------------|------|
| 1 - simple_text | ✗ | ✓ | ❌ 失败 |
| 2 - chinese_text | ✗ | ✓ | ❌ 失败 |
| 3 - mixed_content | ✗ | ✓ | ❌ 失败 |

**失败原因**: JavaScript 无法解密 Java 加密的密文。可能原因：
- Java 和 JavaScript 使用的加密模式参数不一致
- 密文格式编码有差异
- 需要进一步调查

**结论**: ❌ SM2 加密解密在 Hex 模式下存在互通性问题，需要修复。

### SM2 加密签名组合互通性 (Hex 模式)

**测试方法**: 
1. Java 执行加密 + 签名组合操作
2. JavaScript 执行验签 + 解密组合操作
3. 验证解密结果是否与原始明文一致

**测试结果**:

| 测试用例 | Java 加密签名 -> JS 验签解密 | 状态 |
|---------|---------------------------|------|
| 1 - simple_text | ✗ | ❌ 失败 |
| 2 - chinese_text | ✗ | ❌ 失败 |
| 3 - mixed_content | ✗ | ❌ 失败 |

**失败原因**: 由于 SM2 加密解密互通性问题，导致加密签名组合操作失败。

**结论**: ❌ SM2 加密签名组合操作存在互通性问题，需要修复。

---

## SM3 互通性测试

### SM3 哈希互通性

**测试方法**: 
1. Java 和 JavaScript 分别对相同的消息计算 SM3 哈希
2. 比较两种语言实现的哈希值是否一致

**测试结果**:

| 测试用例 | Java 哈希值 | JavaScript 哈希值 | 匹配 | 状态 |
|---------|------------|-----------------|------|------|
| 1 - simple_text | 5734b51e... | 5734b51e... | ✓ | ✅ 通过 |
| 2 - chinese_text | 667d35e7... | 667d35e7... | ✓ | ✅ 通过 |
| 3 - abc (标准向量) | 66c7f0f4... | 66c7f0f4... | ✓ | ✅ 通过 |

**结论**: ✅ SM3 哈希完全互通，且符合国家标准测试向量。

### HMAC-SM3 互通性

**测试方法**: 
1. 使用相同的密钥 (Hex: `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`)
2. Java 和 JavaScript 分别对相同的消息计算 HMAC-SM3
3. 比较两种语言实现的 HMAC 值是否一致

**测试结果**:

| 测试用例 | Java HMAC | JavaScript HMAC | 匹配 | 状态 |
|---------|----------|----------------|------|------|
| 1 - simple_text | 26d4c720... | 26d4c720... | ✓ | ✅ 通过 |
| 2 - chinese_text | 3e327bf9... | 3e327bf9... | ✓ | ✅ 通过 |
| 3 - abc | ✗ (Java 错误) | N/A | ✗ | ❌ 失败 |

**失败原因**: Java 在测试第 3 个用例时出现 Hex 字符串解码错误：`a hexadecimal encoding must have an odd number of characters`。这是测试脚本的问题，不是算法实现的问题。

**结论**: ✅ HMAC-SM3 基本互通，测试脚本需要修复。

---

## SM4 互通性测试

测试在执行 SM4 GCM 加密解密测试时遇到错误，未能完成全部测试。

**遇到的问题**:
- JavaScript 解密结果返回 Base64 格式，但解码时出现 `Incorrect padding` 错误
- 需要进一步调查 JavaScript SM4 GCM 实现的输出格式

**结论**: ⚠️ SM4 互通性测试未完成，需要修复测试脚本或 JavaScript 实现。

---

## 测试总结

### 总体统计

| 算法 | 测试类型 | 测试用例数 | 成功 | 失败 | 未完成 | 成功率 |
|------|---------|-----------|------|------|--------|--------|
| SM2 | 签名验签 (Hex) | 3 | 3 | 0 | 0 | 100% |
| SM3 | 哈希 | 3 | 3 | 0 | 0 | 100% |
| SM3 | HMAC | 3 | 2 | 1* | 0 | 67% |
| SM2 | 加密解密 (Hex) | 3 | 0 | 3 | 0 | 0% |
| SM2 | 加密签名组合 (Hex) | 3 | 0 | 3 | 0 | 0% |
| SM4 | GCM 加密解密 | 1 | 0 | 0 | 1 | N/A |
| **总计** | | **16** | **8** | **7** | **1** | **50%** |

*注：HMAC 测试失败是测试脚本问题，不是算法实现问题。

### 结论

#### ✅ 已验证互通的功能

1. **SM2 签名验签**: Hex 模式下完全互通，Java 签名可以被 JavaScript 正确验证
2. **SM3 哈希**: 完全互通，哈希值一致
3. **HMAC-SM3**: 基本互通（测试脚本有小问题）

#### ❌ 存在问题的功能

1. **SM2 加密解密**: JavaScript 无法解密 Java 加密的密文
   - 可能原因：加密模式参数、密文格式编码有差异
   - 需要进一步调查和修复

2. **SM2 加密签名组合**: 由于加密解密问题导致失败

3. **SM4 GCM**: 测试未完成
   - JavaScript 输出格式可能有问题
   - 需要修复测试脚本或 JavaScript 实现

#### 下一步工作

1. 调查 SM2 加密解密互通性问题
2. 修复 SM4 测试脚本
3. 完成所有测试用例

---

## 如何运行测试

### 前提条件

1. **Java 环境**:
   - JDK 17 或更高版本
   - Maven 3.9+
   - Bouncy Castle 库

2. **Node.js 环境**:
   - Node.js 16 或更高版本
   - npm 10 或更高版本
   - sm-crypto-v2 库

### 构建项目

```bash
# 构建 Java 项目
cd java/crossmool
mvn package -DskipTests

# 构建 JavaScript 项目
cd javascript/crossmool
npm install
npm run build
```

### 运行测试

```bash
# 运行 Python 测试脚本
cd testcase
python run_java_javascript_sm_interop_test.py
```

### 查看结果

测试完成后，将在 `testcase/results/java_javascript_interop/` 目录下生成：

- `test_results.json`: 详细的测试结果（JSON 格式）
- `Java-JavaScript-interop-test-report.md`: 测试报告（Markdown 格式）

---

## 附录

### JavaScript 实现关键点

1. **SM2**:
   - 使用 `sm-crypto-v2` 库
   - 支持 DER 格式密钥解析（X.509/PKCS#8）
   - 使用 C1C3C2 加密模式
   - 使用 DER 格式签名
   - User ID: `1234567812345678`

2. **SM3**:
   - 使用 `sm-crypto-v2` 库
   - 支持 UTF-8 编码
   - 实现标准 HMAC-SM3 算法

3. **SM4 GCM**:
   - 使用 `sm-crypto-v2` 库的 ECB 模式作为基础
   - 手动实现 GCM 模式（CTR + GHASH）
   - IV 长度：12 字节（96 位）
   - Tag 长度：16 字节（128 位）

### Java 实现关键点

1. **SM2**:
   - 使用 Bouncy Castle 库
   - 支持 X.509/PKCS#8 格式密钥
   - 使用 C1C3C2 加密模式
   - 使用 DER 格式签名
   - User ID: `1234567812345678`

2. **SM3**:
   - 使用 Bouncy Castle 库
   - 支持 JCA 标准 API 和原生 API
   - 实现标准 HMAC-SM3 算法

3. **SM4 GCM**:
   - 使用 Bouncy Castle 库的 GCMBlockCipher
   - 支持 JCA 标准 API 和原生 API
   - IV 长度：12 字节（96 位）
   - Tag 长度：128 位（16 字节）

---

**报告生成日期**: 2026 年 6 月 9 日

**测试工具版本**: `run_java_javascript_sm_interop_test.py v1.0`