# Crossmool 跨语言互操作性测试

## 概述

本目录包含 8 种编程语言（Java, C, C++, C#, Go, JavaScript, Python, Rust）实现的 SM2 加解密和签名/验签功能的跨语言互操作性测试脚本。

## 测试场景

1. **Java 加密和签名，其他 7 种语言解密和验签**
2. **C 加密和签名，其他 7 种语言解密和验签**
3. **C++ 加密和签名，其他 7 种语言解密和验签**
4. **C# 加密和签名，其他 7 种语言解密和验签**
5. **Go 加密和签名，其他 7 种语言解密和验签**
6. **JavaScript 加密和签名，其他 7 种语言解密和验签**
7. **Python 加密和签名，其他 7 种语言解密和验签**
8. **Rust 加密和签名，其他 7 种语言解密和验签**

## 数据格式规范

- **输入参数**: UTF-8 字符串
- **输出格式**: 优先 Hex 编码，其次 Base64 编码
- **字符集**: UTF-8

## 测试结构

```
testcase/
├── keys/                    # 共享密钥文件
│   ├── java_keys.json       # Java 生成的密钥对
│   ├── c_keys.json          # C 生成的密钥对
│   ├── cpp_keys.json        # C++ 生成的密钥对
│   ├── csharp_keys.json     # C# 生成的密钥对
│   ├── golang_keys.json     # Go 生成的密钥对
│   ├── javascript_keys.json # JavaScript 生成的密钥对
│   ├── python_keys.json     # Python 生成的密钥对
│   └── rust_keys.json       # Rust 生成的密钥对
├── results/                 # 测试结果目录
│   ├── java_encrypt/        # Java 加密结果
│   ├── c_encrypt/           # C 加密结果
│   ├── cpp_encrypt/         # C++ 加密结果
│   ├── csharp_encrypt/      # C# 加密结果
│   ├── golang_encrypt/      # Go 加密结果
│   ├── javascript_encrypt/  # JavaScript 加密结果
│   ├── python_encrypt/      # Python 加密结果
│   └── rust_encrypt/        # Rust 加密结果
├── test_data.json           # 测试数据（明文）
├── run_all_tests.bat        # Windows 批处理脚本
├── run_all_tests.sh         # Linux/Mac 脚本
└── test_report.md           # 测试报告
```

## 运行测试

### Windows

```batch
cd testcase
run_all_tests.bat
```

### Linux/Mac

```bash
cd testcase
chmod +x run_all_tests.sh
./run_all_tests.sh
```

## 测试结果

测试结果将保存在 `testcase/results/` 目录下，最终报告生成在 `testcase/test_report.md`。