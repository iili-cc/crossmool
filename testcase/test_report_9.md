# 跨语言国密算法互通性测试报告 v9

**Final — 8×8=64组合 × 6类 = 384项**

生成时间: 2026-06-19 12:04:21

## 测试统计

- **SM2 Enc/Dec**: 50/64 PASS
- **SM2 Sign/Verify**: 51/64 PASS
- **SM2 EncSign/VerifyDec**: 50/64 PASS
- **SM3 Hash**: 64/64 PASS
- **SM3-HMAC**: 64/64 PASS
- **SM4 GCM**: 51/64 PASS

**总计: 330/384** ⚠️

## SM2 Enc/Dec

| ↓/→ | **C** | **CPP** | **C#** | **Java** | **Python** | **Go** | **Rust** | **JS** |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **C** | ⭐ | — | ✅ | ✅ | — | ✅ | — | ✅ |
| **CPP** | — | ❌ | ✅ | ✅ | ❌ | ✅ | — | ✅ |
| **C#** | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Java** | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ |
| **Python** | ❌ | ❌ | ✅ | ✅ | ⭐ | ✅ | ❌ | ✅ |
| **Go** | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ |
| **Rust** | — | — | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **JS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ |


## SM2 Sign/Verify

| ↓/→ | **C** | **CPP** | **C#** | **Java** | **Python** | **Go** | **Rust** | **JS** |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **C** | ⭐ | — | ✅ | ✅ | ✅ | ✅ | — | ✅ |
| **CPP** | — | ❌ | ✅ | ✅ | ❌ | ✅ | — | ✅ |
| **C#** | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Java** | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ |
| **Python** | ❌ | ❌ | ✅ | ✅ | ⭐ | ✅ | ❌ | ✅ |
| **Go** | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ |
| **Rust** | — | — | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **JS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ |


## SM2 EncSign/VerifyDec

| ↓/→ | **C** | **CPP** | **C#** | **Java** | **Python** | **Go** | **Rust** | **JS** |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **C** | ⭐ | — | ✅ | ✅ | — | ✅ | — | ✅ |
| **CPP** | — | ❌ | ✅ | ✅ | ❌ | ✅ | — | ✅ |
| **C#** | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Java** | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ |
| **Python** | ❌ | ❌ | ✅ | ✅ | ⭐ | ✅ | ❌ | ✅ |
| **Go** | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ |
| **Rust** | — | — | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **JS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ |


## SM3 Hash

| ↓/→ | **C** | **CPP** | **C#** | **Java** | **Python** | **Go** | **Rust** | **JS** |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **C** | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **CPP** | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **C#** | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Java** | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ |
| **Python** | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ |
| **Go** | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ |
| **Rust** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ |
| **JS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ |


## SM3-HMAC

| ↓/→ | **C** | **CPP** | **C#** | **Java** | **Python** | **Go** | **Rust** | **JS** |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **C** | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **CPP** | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **C#** | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Java** | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ |
| **Python** | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ |
| **Go** | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ |
| **Rust** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ |
| **JS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ |


## SM4 GCM

| ↓/→ | **C** | **CPP** | **C#** | **Java** | **Python** | **Go** | **Rust** | **JS** |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **C** | ⭐ | — | ✅ | ✅ | ✅ | ✅ | — | ✅ |
| **CPP** | — | ❌ | ✅ | ✅ | ❌ | ✅ | — | ✅ |
| **C#** | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Java** | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ | ✅ | ✅ |
| **Python** | ❌ | ❌ | ✅ | ✅ | ⭐ | ✅ | ❌ | ✅ |
| **Go** | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ | ✅ | ✅ |
| **Rust** | — | — | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |
| **JS** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⭐ |

---

## 各语言自测详细
- **C**: enc=PASS sig=PASS esvd=PASS sm3=PASS hmac=PASS sm4=PASS
- **CPP**: enc=N/A sig=N/A esvd=N/A sm3=N/A hmac=N/A sm4=N/A
- **C#**: enc=PASS sig=PASS esvd=PASS sm3=PASS hmac=PASS sm4=PASS
- **Java**: enc=PASS sig=PASS esvd=PASS sm3=PASS hmac=PASS sm4=PASS
- **Python**: enc=PASS sig=PASS esvd=PASS sm3=PASS hmac=PASS sm4=PASS
- **Go**: enc=PASS sig=PASS esvd=PASS sm3=PASS hmac=PASS sm4=PASS
- **Rust**: enc=N/A sig=N/A esvd=N/A sm3=N/A hmac=N/A sm4=N/A
- **JS**: enc=PASS sig=PASS esvd=PASS sm3=PASS hmac=PASS sm4=PASS

---

## 交叉验证详细 (Python ↔ All)

### Python → C
- SM2 Dec: FAIL
- SM2 Verify: FAIL
- SM4 Dec: FAIL
- SM2 EncSign/VerifyDec: FAIL

### C → Python
- SM2 Dec: FAIL:'utf-8' codec can't decode byte 0x82 in position 2: invalid start byte
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: FAIL:'utf-8' codec can't decode byte 0x82 in position 2: invalid start byte

### Python → CPP
- SM2 Dec: FAIL
- SM2 Verify: FAIL
- SM4 Dec: FAIL
- SM2 EncSign/VerifyDec: FAIL

### CPP → Python
- SM2 Dec: FAIL
- SM2 Verify: FAIL
- SM4 Dec: FAIL
- SM2 EncSign/VerifyDec: FAIL

### Python → C#
- SM2 Dec: PASS
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: PASS

### C# → Python
- SM2 Dec: PASS
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: PASS

### Python → Java
- SM2 Dec: PASS
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: PASS

### Java → Python
- SM2 Dec: PASS
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: PASS

### Python → Go
- SM2 Dec: PASS
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: PASS

### Go → Python
- SM2 Dec: PASS
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: PASS

### Python → Rust
- SM2 Dec: FAIL
- SM2 Verify: FAIL
- SM4 Dec: FAIL
- SM2 EncSign/VerifyDec: FAIL

### Rust → Python
- SM2 Dec: FAIL
- SM2 Verify: FAIL
- SM4 Dec: FAIL
- SM2 EncSign/VerifyDec: FAIL

### Python → JS
- SM2 Dec: PASS
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: PASS

### JS → Python
- SM2 Dec: PASS
- SM2 Verify: PASS
- SM4 Dec: PASS
- SM2 EncSign/VerifyDec: PASS

---
*报告生成: 2026-06-19 12:04:21 | 测试框架 v9*