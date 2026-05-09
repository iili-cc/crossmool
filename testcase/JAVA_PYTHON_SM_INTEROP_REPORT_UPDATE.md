# Java-Python SM2/SM3/SM4 互操作性测试报告（更新版）

## 测试概述

**测试日期**: 2026-05-09  
**测试目的**: 验证 Java (BouncyCastle) 和 Python (gmssl) 实现的国密 SM2/SM3/SM4 算法的互操作性  
**最终结果**: **6/6 测试全部通过** ✓✓✓

## 重要更新 (2026-05-09 17:45)

### SM4 功能验证 - 误判更正

**之前报告**: gmssl.sm4.CryptSM4.crypt_ecb() 存在 bug，Python 加密无法使用

**实际验证结果**: ✅ **gmssl 库的 SM4 ECB 功能完全正常**

验证测试:
```bash
# Python 自加密自解密
✅ Python encrypt -> Python decrypt: PASS

# Java 加密 Python 解密
✅ Java encrypt -> Python decrypt: PASS

# Python 加密 Java 解密
✅ Python encrypt -> Java decrypt: PASS

# 密文一致性验证
✅ Python ciphertext == Java ciphertext: IDENTICAL
```

**密文对比**:
```
密钥：9bac79cd836f9ff36d795d9d96b3304f
明文：Hello, Cross-Language Interop Test!

Python 加密输出：40e7984272876a52b4f3d2f89b14684c695fb9bbdebdd8c15ca03f44fcfdc7dc89dbc8bfacdabcf7348d866c8e1a0c64
Java 加密输出：   40e7984272876a52b4f3d2f89b14684c695fb9bbdebdd8c15ca03f44fcfdc7dc89dbc8bfacdabcf7348d866c8e1a0c64
结果：完全一致 ✅
```

## 完整测试结果

| 测试项 | 方向 | 结果 | 备注 |
|--------|------|------|------|
| SM2 加密 | Java→Python | ✅ PASS | 需去除 04 前缀 |
| SM2 加密 | Python→Java | ✅ PASS | 直接使用 |
| SM2 签名 | Java→Python | ✅ PASS | DER 格式兼容 |
| SM2 签名 | Python→Java | ✅ PASS | DER 格式兼容 |
| SM3 摘要 | Java→Python | ✅ PASS | 完全兼容 |
| HMAC-SM3 | Java→Python | ✅ PASS | 需 SM3Digest 类 |
| SM4 ECB | Java→Python | ✅ PASS | PKCS7 填充 |
| SM4 ECB | Python→Java | ✅ PASS | PKCS7 填充 |

## 测试文件

### Python 测试
- `testcase/test_sm4_interop.py` - SM4 互操作性测试
- `testcase/test_sm4_debug.py` - SM4 调试测试
- `testcase/test_java_python_sm_interop.py` - 完整互操作性测试

### Java 测试
- `testcase/TestPythonSM4.java` - 验证 Python 加密输出
- `testcase/GenerateAndTest.java` - Java SM2 自测试

## 结论

**Java-Python 国密算法互操作性：完全通过** ✅

所有算法（SM2/SM3/SM4/HMAC-SM3）在 Java 和 Python 之间都可以完美互操作：
- ✅ SM2 加密/解密：双向可用
- ✅ SM2 签名/验证：双向可用
- ✅ SM3 摘要：完全一致
- ✅ HMAC-SM3：完全一致
- ✅ SM4 ECB 加密/解密：双向可用，密文完全一致

## 技术要点

### SM4 互操作关键配置

**Java**:
```java
// 使用 JCA API，ECB 模式，PKCS7 填充
SM4Util.encryptEcbJca(keyBytes, plaintext)
SM4Util.decryptEcbJca(keyBytes, ciphertextHex)
```

**Python**:
```python
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT, PKCS7

# 加密
sm4 = CryptSM4(SM4_ENCRYPT, PKCS7)
sm4.set_key(key_bytes, SM4_ENCRYPT)
ciphertext = sm4.crypt_ecb(plaintext_bytes)

# 解密
sm4 = CryptSM4(SM4_DECRYPT, PKCS7)
sm4.set_key(key_bytes, SM4_DECRYPT)
plaintext = sm4.crypt_ecb(ciphertext_bytes)
```

**关键点**:
1. 双方都使用 PKCS7 填充
2. 密钥长度必须为 16 字节 (128 位)
3. 数据以字节数组形式传递
4. 输出为原始字节，需要 HEX 编码后传输

## 下一步

1. ✅ Java-Python 互操作性测试：完成
2. ⏭️ Java-C 互操作性测试：待进行
3. ⏭️ C-Python 互操作性测试：待进行
4. ⏭️ 性能对比测试：可选

## 附录：验证命令

### 运行 Python 测试
```bash
cd testcase
python test_sm4_interop.py
```

### 运行 Java 测试
```bash
cd testcase
javac -encoding UTF-8 -cp "../java/crossmool/target/classes;../java/crossmool/target/dependency/*" TestPythonSM4.java
java -cp ".;../java/crossmool/target/classes;../java/crossmool/target/dependency/*" TestPythonSM4
```

### 预期输出
```
Test Python SM4 -> Java Decrypt
================================
Key: 9bac79cd836f9ff36d795d9d96b3304f
Python ciphertext: 40e7984272876a52b4f3d2f89b14684c...
Expected message: Hello, Cross-Language Interop Test!

Decrypting with Java SM4Util.decryptEcbJca()...
Decrypted: Hello, Cross-Language Interop Test!

[PASS] Python->Java SM4 interop works!