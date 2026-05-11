# crossmool 国密算法 Java ↔ C++ 双向互通性测试报告

**报告日期：** 2026-05-11  
**测试结果：** 30/30 全部通过 (100.0%)  
**测试环境：** Windows x64, JDK 21.0.1+12, MSVC 19.50, GmSSL

---

## 1. 测试概述

本报告记录 crossmool 项目中 **Java (BouncyCastle 1.82)** 与 **C++ (GmSSL)** 实现的国密算法跨语言双向互通性测试。涵盖 SM2/SM3/SM4 共三种算法，7类操作，3种文本类型（英文/简体中文/混合），双向全覆盖。

### 1.1 测试架构

```
┌─────────────────────────────────────────┐
│      Java (BouncyCastle 1.82)          │
│  SM2Util / SM3Util / SM4Util           │
│  JavaCLIHelper (CLI 辅助工具)            │
└──────────────┬──────────────────────────┘
               │   Python 编排脚本
               │   (run_java_cpp_full_interop_v3.py)
┌──────────────┴──────────────────────────┐
│      C++ (interoperability_test.exe)    │
│  SM2Util / SM3Util / SM4Util           │
│  GmSSL 底层 → crossmool.dll            │
└─────────────────────────────────────────┘
```

### 1.2 测试文本

| # | 类型 | 明文 |
|---|------|------|
| 1 | 英文 (ASCII) | `Hello, Cross-Language Interop Test!` |
| 2 | 简体中文 (UTF-8) | `国密算法跨语言互通测试：简体中文` |
| 3 | 混合 (ASCII + 繁體) | `Mixed content 123!@#$% 混合測試數據` |

---

## 2. 测试结果总表

### SM2 非对称加密与数字签名

| # | 操作 | 方向 | 文本#1 | 文本#2 | 文本#3 |
|---|------|------|--------|--------|--------|
| 1 | encrypt/decrypt | **Java → C++** | PASS | PASS | PASS |
| 2 | encrypt/decrypt | **C++ → Java** | PASS | PASS | PASS |
| 3 | sign/verify | **Java → C++** | PASS | PASS | PASS |
| 4 | sign/verify | **C++ → Java** | PASS | PASS | PASS |
| 5 | enc_sign/ver_dec | **Java → C++** | PASS | PASS | PASS |
| 6 | enc_sign/ver_dec | **C++ → Java** | PASS | PASS | PASS |

### SM3 杂凑算法

| # | 操作 | 方向 | 文本#1 | 文本#2 | 文本#3 |
|---|------|------|--------|--------|--------|
| 7 | digest 摘要 | **Java ↔ C++** | PASS | PASS | PASS |
| 8 | HMAC-SM3 | **Java ↔ C++** | PASS | PASS | PASS |

### SM4 对称加密

| # | 操作 | 方向 | 文本#1 | 文本#2 | 文本#3 |
|---|------|------|--------|--------|--------|
| 9 | encrypt/decrypt | **Java → C++** | PASS | PASS | PASS |
| 10 | encrypt/decrypt | **C++ → Java** | PASS | PASS | PASS |

---

## 3. 各算法详细互操作结果

### 3.1 SM2 加密/解密

| 测试项 | 方向 | 技术要点 | 结果 |
|--------|------|----------|------|
| Java 加密 → C++ 解密 | Java→C++ | Java C1C3C2 密文，C++ 自动识别并转换 | ✅ |
| C++ 加密 → Java 解密 | C++→Java | C++ GmSSL DER 密文 → Python DER→C1C3C2 转换 → Java 解密 | ✅ |

**密文格式兼容方案：**
- Java BouncyCastle 输出：C1C3C2 RAW 格式 (`04‖x[32]‖y[32]‖C3[32]‖C2[N]`)
- C++ GmSSL 输出：DER SEQUENCE 格式 (`30‖len‖02‖...`)
- **互转方案：** C++ 解密端已内置 `sm2_raw_c1c3c2_to_der()`；C++→Java 方向由 Python 编排脚本执行 `der_to_c1c3c2()` 转换

### 3.2 SM2 签名/验签

| 测试项 | 方向 | 技术要点 | 结果 |
|--------|------|----------|------|
| Java 签名 → C++ 验签 | Java→C++ | DER 签名格式直接兼容 | ✅ |
| C++ 签名 → Java 验签 | C++→Java | DER 签名格式直接兼容 | ✅ |

- 双方均使用 DER-encoded `SEQUENCE{INTEGER r, INTEGER s}` 签名格式
- SM2 USER_ID 固定为 `"1234567812345678"`，双方一致
- 无需任何格式转换

### 3.3 SM2 加密+签名 / 验签+解密

| 测试项 | 方向 | 签名内容 | 结果 |
|--------|------|----------|------|
| Java enc_sign → C++ ver_dec | Java→C++ | 签名对象：C1C3C2 密文 Hex 字符串 UTF-8 字节 | ✅ |
| C++ enc_sign → Java ver_dec | C++→Java | 签名对象：DER 密文 Hex 字符串 UTF-8 字节 | ✅ |

> 注意：`encryptSign` 签名的对象是密文 hex 字符串（而非原始明文），双方使用对应格式的 hex 字符串签名并验证。

### 3.4 SM3 摘要

| 测试项 | 比对内容 | 结果 |
|--------|----------|------|
| Java ↔ C++ | `Hello, Cross-Language Interop Test!` → `b723fc24a1d6ad071229bfee3ef667ec3df3f79801a3c41e622bd55a3e466b37` | ✅ 完全一致 |
| Java ↔ C++ | `国密算法跨语言互通测试：简体中文` → `49ca4fc4c4fc2cb67db9fb382d12f2e8bdb8402379ebf0d3d63e2a27c08a121b` | ✅ 完全一致 |
| Java ↔ C++ | `Mixed content 123!@#$% 混合測試數據` → `1e022b6e231340ab2f621cbac80c5b69f5accd6cb2b66d9bceafe2ca77e842cb` | ✅ 完全一致 |

### 3.5 HMAC-SM3

| 测试项 | HMAC Key | 结果 |
|--------|----------|------|
| Java ↔ C++ (英文) | `0123456789abcdef0123456789abcdef` → `00e9bd6012151a7ba4a1701b5ce4bdf81f8d44fcaaa2cc41c0f1c088a962daf3` | ✅ 完全一致 |
| Java ↔ C++ (中文) | `0123456789abcdef0123456789abcdef` → `2b4304b6c9de5c4df66b920dae47d0a1a95e0b3c6b067321b282d5a2f5eb4cf1` | ✅ 完全一致 |
| Java ↔ C++ (混合) | `0123456789abcdef0123456789abcdef` → `3d9f9a9a7bcc5c508e94ad0578dda8f28c3dc30b7d151a1c4e893e1a3f2d2a4e` | ✅ 完全一致 |

### 3.6 SM4 ECB 加密/解密

| 测试项 | 方向 | 密钥 | 模式 | 结果 |
|--------|------|------|------|------|
| Java 加密 → C++ 解密 | Java→C++ | `8091d00c09ba74cfe6da26b7daa7ce39` | ECB / PKCS7Padding | ✅ |
| C++ 加密 → Java 解密 | C++→Java | `8091d00c09ba74cfe6da26b7daa7ce39` | ECB / PKCS7Padding | ✅ |

> SM4 采用固定测试密钥（16 字节），ECB 模式 + PKCS7 填充。双方输出密文完全一致。

---

## 4. 测试执行详情

### 4.1 测试编排脚本

- **脚本路径：** `testcase/run_java_cpp_full_interop_v3.py`
- **Java CLI 辅助工具：** `testcase/java_test_classes/JavaCLIHelper.java`
- **C++ 互操作命令行工具：** `cpp/crossmool/build/bin/Release/interoperability_test.exe`
- **临时工作目录：** `testcase/.interop_temp/`
- **结果输出：** `testcase/results/java_cpp_full_interop_v3_*.json`

### 4.2 测试流程

```
Phase 1: Java 生成 SM2 密钥对 (X.509/PKCS#8 DER Hex)
Phase 2: SM2 encrypt/decrypt — Java→C++ 和 C++→Java, 各 3 条文本
Phase 3: SM2 sign/verify — Java→C++ 和 C++→Java, 各 3 条文本
Phase 4: SM2 encrypt_sign/verify_decrypt — Java→C++ 和 C++→Java, 各 3 条文本
Phase 5: SM3 digest — Java↔C++ 双向比对, 3 条文本
Phase 6: HMAC-SM3 — Java↔C++ 双向比对, 3 条文本
Phase 7: SM4 encrypt/decrypt — Java→C++ 和 C++→Java, 各 3 条文本
```

---

## 5. 跨语言互通性结论

| 算法 | 操作 | Java ↔ C++ | 格式兼容性 | 备注 |
|------|------|:----------:|------------|------|
| **SM2** | 加密/解密 | ✅ **完全互通** | Java C1C3C2 ↔ C++ DER（需转换） | 解密端自动识别并转换 |
| **SM2** | 签名/验签 | ✅ **完全互通** | 双方均为 DER 格式，直接兼容 | USER_ID = `1234567812345678` |
| **SM2** | enc_sign/ver_dec | ✅ **完全互通** | 签名对象为密文 hex 字符串 | hex 字符串 UTF-8 字节签名 |
| **SM3** | 摘要 | ✅ **完全互通** | 双方输出完全一致 | 无需转换 |
| **HMAC-SM3** | HMAC | ✅ **完全互通** | 双方输出完全一致 | 无需转换 |
| **SM4-ECB** | 加密/解密 | ✅ **完全互通** | PKCS7 填充完全兼容 | ECB 模式 |

---

## 6. 修复的问题汇总

本次测试过程中发现并修复了以下问题：

| # | 模块 | 问题描述 | 修复方案 | 影响 |
|---|------|----------|----------|------|
| 1 | C++ `SM2Util.cpp` | `encryptToBytes(string,string)` 将 HEX 字符串当作 UTF-8 字节传入（182 字节 vs 91 字节） | 增加 `HexUtil::decodeHexStr` 解码 | SM2 公钥解析 |
| 2 | C++ `SM2Util.cpp` | Java 生成的 ECPrivateKey 缺少 `[0] EXPLICIT ECParameters`，GmSSL 无法解析 | 增加手动 ASN.1 解析回退路径 | SM2 签名私钥解析 |
| 3 | C++ `SM2Util.cpp` | Java RAW C1C3C2 密文与 GmSSL DER SEQUENCE 不兼容 | 增加 `sm2_raw_c1c3c2_to_der()` 自动转换 | SM2 解密 |
| 4 | C++ `SM4Util.cpp` | PKCS7 填充未处理块对齐情况（`remainder==0` 时未加满块填充） | `paddingLen = blockSize - (size % blockSize)` 统一处理 | SM4 加密输出 |
| 5 | Java `SM4Util.java` | `decryptEcbNative` 未正确获取 `doFinal` 返回值，导致对齐块解密后包含填充字节 | 使用 `len += doFinal()` 并用 `new String(output,0,len,UTF_8)` | SM4 解密 |
| 6 | Java CLI (Windows) | `System.out` 管道输出默认使用系统编码(GBK)，中文被 Python UTF-8 解码损坏 | 添加 `-Dsun.stdout.encoding=UTF-8` JVM 参数 | 所有 CLI 命令输出 |

### 6.1 额外添加的辅助功能

| 功能 | 描述 |
|------|------|
| `JavaCLIHelper` (Java CLI 辅助工具) | 暴露 SM2/SM3/SM4 所有操作的标准命令行接口 |
| `sm2-verify-hex` | 支持原始字节级别的签名验证（hex 编码输入） |
| `sm2-encrypt-hex` / `sm2-decrypt-hex` | 支持 hex 编码输入/输出，规避 Windows 命令行编码问题 |
| `der_to_c1c3c2()` (Python) | GmSSL DER SEQUENCE → Java C1C3C2 RAW 格式转换器 |
| `run_java_cpp_full_interop_v3.py` | Python 编排脚本，全自动执行 30 条测试并生成结果 JSON |

---

## 7. 测试环境详情

### 7.1 软件版本

| 组件 | 版本 | 路径 |
|------|------|------|
| JDK | OpenJDK 21.0.1+12 (Temurin) | `H:/Programs/Java/jdk-21.0.1+12/` |
| MSVC | 19.50.35729 (Build Tools) | `H:/Programs/VisualStudio/BuildTools/` |
| CMake | VS 2022 bundled | cmake 3.28+ |
| BouncyCastle | bcprov-jdk18on-1.82.jar | `java/crossmool/target/dependency/` |
| Python | 3.12.10 | `H:/Programs/Python3/python.exe` |

### 7.2 关键编译产物

| 文件 | 路径 | 用途 |
|------|------|------|
| `interoperability_test.exe` | `cpp/crossmool/build/bin/Release/` | C++ 互操作 CLI 工具 |
| `crossmool.dll` | `cpp/crossmool/build/lib/Release/` | C++ SM2/SM3/SM4 库 |
| `gmssl.dll` | `cpp/crossmool/build/bin/Release/` | GmSSL 底层库 |
| `JavaCLIHelper.class` | `testcase/java_test_classes/` | Java CLI 辅助工具 |
| SM2Util/SM3Util/SM4Util | `java/crossmool/target/classes/` | Java 国密算法实现 |

---

## 8. 已知限制

1. **SM4 其他模式：** 仅测试了 ECB 模式，CBC/CTR/GCM 未覆盖
2. **SM2 性能：** 未进行加解密速度和吞吐量基准测试
3. **大文件：** 未测试超大文本（MB级）加解密场景
4. **密钥格式：** 仅测试 Hex 编码的 X.509/PKCS#8 DER 密钥格式

---

## 9. 测试文件索引

| 文件 | 描述 |
|------|------|
| `testcase/run_java_cpp_full_interop_v3.py` | Java ↔ C++ 全量互通测试编排脚本 |
| `testcase/java_test_classes/JavaCLIHelper.java` | Java CLI 辅助工具源码 |
| `testcase/results/java_cpp_full_interop_v3_*.json` | 测试结果 JSON |
| `testcase/SM_INTEROP_TEST_REPORT.md` | 先前 Java ↔ C 互通测试报告 (10/10) |
| `cpp/crossmool/tests/interoperability_test.cpp` | C++ 互操作 CLI 工具源码 |
| `cpp/crossmool/src/SM2Util.cpp` | C++ SM2 工具类 (含 DER→C1C3C2 及私钥解析修复) |
| `cpp/crossmool/src/SM4Util.cpp` | C++ SM4 工具类 (含 PKCS7 填充修复) |
| `java/crossmool/src/main/java/cc/iili/tools/crossmool/tool/SM4Util.java` | Java SM4 工具类 (含 doFinal 长度修复) |

---

*报告由 run_java_cpp_full_interop_v3.py 驱动生成，2026-05-11*
*crossmool — 国密算法跨语言互通验证项目*
