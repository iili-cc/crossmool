# Java-JavaScript SM2/SM3/SM4 互通性测试报告

## 测试概述

本报告测试了 Java 和 JavaScript 两种语言实现的 SM2、SM3、SM4 算法的互通性。

### 测试环境

- Java 版本：JDK 17
- Node.js 版本：v22.18.0

## SM2 互通性测试

### Encrypt Hex

- 测试用例数：3
- 成功：3
- 失败：0
- 成功率：100.0%

- ✓ 测试用例 1: success
- ✓ 测试用例 2: success
- ✓ 测试用例 3: success

### Sign Hex

- 测试用例数：3
- 成功：3
- 失败：0
- 成功率：100.0%

- ✓ 测试用例 1: success
- ✓ 测试用例 2: success
- ✓ 测试用例 3: success

### Encrypt Sign Hex

- 测试用例数：3
- 成功：3
- 失败：0
- 成功率：100.0%

- ✓ 测试用例 1: success
- ✓ 测试用例 2: success
- ✓ 测试用例 3: success

## SM3 互通性测试

### Digest

- 测试用例数：3
- 成功：3
- 失败：0
- 成功率：100.0%

- ✓ 测试用例 1: success
- ✓ 测试用例 2: success
- ✓ 测试用例 3: success

### Hmac

- 测试用例数：3
- 成功：3
- 失败：0
- 成功率：100.0%

- ✓ 测试用例 1: success
- ✓ 测试用例 2: success
- ✓ 测试用例 3: success

## SM4 互通性测试

### 加密解密互通性

- 测试用例数：3
- 成功：3
- 失败：0
- 成功率：100.0%

- ✓ 测试用例 1: success
- ✓ 测试用例 2: success
- ✓ 测试用例 3: success

## 测试总结

- 总测试用例数：18
- 成功：18
- 失败：0
- 成功率：100.0%

## 结论

✅ **所有测试通过！** Java 和 JavaScript 的 SM2/SM3/SM4 实现完全互通。
