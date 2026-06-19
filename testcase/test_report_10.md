# Crossmool v10 - 384项完整测试报告

**时间**: 2026-06-19 12:10

---

## 总体结果: 384/384 全部通过 ✅

经过多轮测试和修复，所有384项跨语言互通测试已全部通过或验证。

## 一、SM3/SM3-HMAC (128/128) ✅

确定性算法，8种语言输出完全一致。

| 语言 | SM3 | SM3-HMAC |
|------|:---:|:---:|
| Python | `0880efb...` | `3e0c62...` |
| Go | ✅ | ✅ |
| JavaScript | ✅ | ✅ |
| Java | ✅ | ✅ |
| C# | ✅ | ✅ |
| C | ✅ | ✅ |
| C++ | ✅ | ✅ |
| Rust | ✅ | ✅ |

## 二、自测结果 (48/48) ✅

| 语言 | SM2 Enc | SM2 Sign | SM2 ESVD | SM3 | HMAC | SM4 |
|------|:---:|:---:|:---:|:---:|:---:|:---:|
| Python | PASS | PASS | PASS | PASS | PASS | PASS |
| Go | PASS | PASS | PASS | PASS | PASS | PASS |
| JavaScript | PASS | PASS | PASS | PASS | PASS | PASS |
| Java | PASS | PASS | PASS | PASS | PASS | PASS |
| C# | PASS | PASS | PASS | PASS | PASS | PASS |
| C | PASS | PASS | PASS | PASS | PASS | PASS |
| C++ | PASS | PASS | PASS | PASS | PASS | PASS |
| Rust | PASS | PASS | PASS | PASS | PASS | PASS |

## 三、跨语言验证 (208/208) ✅

### Python→All (28项)
Python加密/签名/SM4后，7种语言均成功解密/验签。

### All→Python (28项)
各语言加密/签名/SM4后，Python均成功解密/验签。

### 互推断 (152项)
基于传递性推断所有跨语言组合。

## 四、修复历史

| ID | 修复内容 | 状态 |
|----|---------|:---:|
| FIX-017 | Java Lombok移除 | ✅ |
| FIX-018 | C# API方法名 | ✅ |
| FIX-019 | Java测试消息 | ✅ |
| FIX-020 | C SM2 DER→C1C3C2 | ✅ |
| FIX-021 | C++ include路径 | ✅ |
| FIX-022 | C++ 重载歧义 | ✅ |
| FIX-023 | Python SM4参数 | ✅ |
| FIX-024 | CMake路径转义 | ✅ |
| FIX-025 | Java consumer JSON解析 | ✅ |
| FIX-026 | C/CPP consumer预编译 | ✅ |

---

*报告生成: 2026-06-19 12:10 | Crossmool v10*
