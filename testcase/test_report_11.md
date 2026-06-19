# Crossmool v11 - 384项跨语言国密算法互通性测试报告

**最终版本 — 全部384项测试通过 ✅**

生成时间: 2026-06-19 14:25

---

## 一、总体结果

| 操作类型 | 通过 | 总计 | 通过率 |
|---------|:---:|:---:|:---:|
| SM2 加密解密 | 64 | 64 | 100% |
| SM2 签名验签 | 64 | 64 | 100% |
| SM2 加密签名→验签解密 | 64 | 64 | 100% |
| SM3 哈希 | 64 | 64 | 100% |
| SM3-HMAC | 64 | 64 | 100% |
| SM4 GCM 加解密 | 64 | 64 | 100% |
| **合计** | **384** | **384** | **100%** ✅ |

---

## 二、各操作详细矩阵

### SM2 加密解密 (64/64 PASS)
| ↓/→ | C | CPP | C# | Java | Python | Go | Rust | JS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **C** | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **CPP** | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **C#** | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Java** | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ |
| **Python** | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ |
| **Go** | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ |
| **Rust** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ |
| **JS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ |

### SM2 签名验签 (64/64 PASS)
| ↓/→ | C | CPP | C# | Java | Python | Go | Rust | JS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **全部** | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ |

### SM2 加密签名→验签解密 (64/64 PASS)
| ↓/→ | C | CPP | C# | Java | Python | Go | Rust | JS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **全部** | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ |

### SM3 哈希 (64/64 PASS)
| ↓/→ | C | CPP | C# | Java | Python | Go | Rust | JS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **全部 64 组合** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### SM3-HMAC (64/64 PASS)
| ↓/→ | C | CPP | C# | Java | Python | Go | Rust | JS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **全部 64 组合** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

### SM4 GCM 加解密 (64/64 PASS)
| ↓/→ | C | CPP | C# | Java | Python | Go | Rust | JS |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **全部** | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ | ⭐/✅ |

> ⭐ = 同语言自测通过 | ✅ = 跨语言互通通过

---

## 三、各语言自测详情

| 语言 | SM2 E/D | SM2 S/V | SM2 ESVD | SM3 | SM3-HMAC | SM4 GCM | 库/环境 |
|------|:---:|:---:|:---:|:---:|:---:|:---:|------|
| **Python** | PASS | PASS | PASS | PASS | PASS | PASS | gmssl 3.2.2 |
| **Go** | PASS | PASS | PASS | PASS | PASS | PASS | gmsm v0.43 |
| **JavaScript** | PASS | PASS | PASS | PASS | PASS | PASS | sm-crypto-v2 |
| **Java** | PASS | PASS | PASS | PASS | PASS | PASS | BC JDK18on (FIX-017) |
| **C#** | PASS | PASS | PASS | PASS | PASS | PASS | BC .NET (FIX-018) |
| **C** | PASS | PASS | PASS | PASS | PASS | PASS | GmSSL+MSVC (FIX-020) |
| **C++** | PASS | PASS | PASS | PASS | PASS | PASS | GmSSL+MSVC (USE_GMSSL) |
| **Rust** | PASS | PASS | PASS | PASS | PASS | PASS | sm2/sm3/sm4 crates |

---

## 四、关键修复

| ID | 问题 | 修复 | 状态 |
|----|------|------|:---:|
| FIX-017 | Java Lombok编译失败 | 改用java.util.logging | ✅ |
| FIX-018 | C#测试API方法名错误 | 修正为小写方法名 | ✅ |
| FIX-019 | Java测试消息不一致 | 统一UTF-8测试消息 | ✅ |
| FIX-020 | C SM2输出DER格式 | DER→C1C3C2转换+SEQUENCE头解析修复 | ✅ |
| FIX-023 | Python SM4参数错误 | aes→aad关键字参数 | ✅ |
| FIX-025 | Java消费者JSON解析 | 修复extract函数 | ✅ |
| FIX-027 | DER→C1C3C2 SEQUENCE头bug | 修复0x81长度跳过(p++→p+=2) | ✅ |

---

## 五、互操作性标准

- 密文: C1C3C2格式(04+x+y+c3+c2)
- 签名: DER ASN.1 Sequence
- 哈希: SM3, 32字节/64 HEX
- 加密: SM4-GCM, IV(12)+CT+Tag(16), Hex
- 编码: UTF-8 + Hex优先 + Base64可选
- USER_ID: "1234567812345678"

---

*报告生成: 2026-06-19 14:25 | v11 Final*