# 跨语言 SM2 互通性测试错误报告

**生成时间**: 2026-04-29 22:23:32  
**测试模式**: 完整测试（加密 + 验证）

---

## 一、加密测试错误（8 种语言 × 5 个测试用例 = 40 组）

### 1. Java 加密测试失败
- **脚本**: `testcase/java_interop_test.py`
- **错误**: 结果 0/0 成功
- **可能原因**:
  - Java 编译失败或运行时错误
  - 密钥文件格式不正确
  - 测试类 `SM2InteropTest.java` 路径或类名错误
- **建议修复**:
  1. 单独运行 `python testcase/java_interop_test.py` 查看详细错误
  2. 检查 `testcase/keys/java/keys.json` 密钥格式
  3. 确认 `testcase/java_test_classes/SM2InteropTest.java` 存在且可编译

### 2. C 语言加密测试失败
- **脚本**: `testcase/c_interop_test.py`
- **错误**: 结果 0/0 成功
- **可能原因**:
  - MSVC 编译器未正确配置
  - `crossmool.dll` 路径不正确或缺失
  - C 程序编译失败
- **建议修复**:
  1. 确认 `c/crossmool/crossmool.dll` 存在
  2. 检查 MSVC 编译器环境变量
  3. 单独运行 `python testcase/c_interop_test.py` 查看编译错误

### 3. C++ 加密测试失败
- **脚本**: `testcase/cpp_interop_test.py`
- **错误**: 结果 0/0 成功
- **可能原因**:
  - `interoperability_test.exe` 未编译或路径错误
  - C++ 项目依赖未正确链接
- **建议修复**:
  1. 确认 `cpp/crossmool/` 目录下有编译好的可执行文件
  2. 运行 `cpp/crossmool/build_cpp.bat` 重新编译
  3. 检查 GmSSL 库是否正确安装

### 4. C# 加密测试失败
- **脚本**: `testcase/csharp_interop_test.py`
- **错误**: 结果 0/0 成功
- **可能原因**:
  - `Crossmool.Crypto.dll` 未编译或路径错误
  - .NET 环境未正确配置
- **建议修复**:
  1. 确认 `csharp/crossmool/src/Crossmool.Crypto/bin/` 下有编译好的 DLL
  2. 运行 `dotnet build` 编译 C# 项目
  3. 检查 `dotnet --version` 确认环境

### 5. Go 加密测试失败
- **脚本**: `testcase/golang_interop_test.py`
- **错误**: 结果 0/0 成功
- **可能原因**:
  - Go 模块未正确初始化
  - Go 程序编译失败
  - 密钥格式不兼容
- **建议修复**:
  1. 在 `golang/crossmool/` 目录运行 `go build`
  2. 检查 `go.mod` 依赖是否正确
  3. 单独运行 `python testcase/golang_interop_test.py` 查看错误

### 6. JavaScript 加密测试失败
- **脚本**: `testcase/javascript_interop_test.py`
- **错误**: 结果 0/0 成功
- **可能原因**:
  - Node.js 环境未配置
  - TypeScript 未编译
  - 依赖包未安装
- **建议修复**:
  1. 在 `javascript/crossmool/` 目录运行 `npm install`
  2. 运行 `npm run build` 编译 TypeScript
  3. 检查 `node --version` 和 `npm --version`

### 7. Python 加密测试失败
- **脚本**: `testcase/python_interop_test.py`
- **错误**: `ModuleNotFoundError: No module named 'crossmool'`
- **详细错误**:
  ```
  from crossmool.sm2_util import SM2Util
  ModuleNotFoundError: No module named 'crossmool'
  ```
- **可能原因**:
  - Python 包结构不正确
  - `python/crossmool/src/` 缺少 `__init__.py` 或包结构错误
  - 相对导入失败
- **建议修复**:
  1. 确认 `python/crossmool/src/crossmool/` 目录存在
  2. 将所有 `.py` 文件（`sm2_util.py`, `sm3_util.py`, `sm4_util.py`, `encoding.py`, `der.py`）移动到 `python/crossmool/src/crossmool/` 目录
  3. 在 `python/crossmool/src/crossmool/__init__.py` 中正确导出类
  4. 重新运行 `pip install -e python/crossmool`

### 8. Rust 加密测试失败
- **脚本**: `testcase/rust_interop_test.py`
- **错误**: 脚本执行超时
- **可能原因**:
  - Rust 项目编译时间过长
  - `cargo build` 卡住或失败
  - `target/release` 目录为空
- **建议修复**:
  1. 在 `rust/crossmool/` 目录运行 `cargo build --release`
  2. 确认 `target/release/` 下有可执行文件
  3. 检查 `Cargo.toml` 依赖是否正确
  4. 增加脚本超时时间或优化编译配置

---

## 二、验证测试错误（由于加密测试全部失败，验证测试无法执行）

所有 8 种语言的验证测试（共 280 组）都未执行，因为：
- 验证测试需要依赖加密测试生成的密文和签名文件
- 加密测试输出目录为空，导致验证测试无数据可验证

**验证测试脚本**:
- `testcase/c_verify_decrypt_test.py`
- `testcase/cpp_verify_decrypt_test.py`
- `testcase/csharp_verify_decrypt_test.py`
- `testcase/golang_verify_decrypt_test.py`
- `testcase/java_verify_decrypt_test.py`
- `testcase/javascript_verify_decrypt_test.py`
- `testcase/python_verify_decrypt_test.py`
- `testcase/rust_verify_decrypt_test.py`

---

## 三、修复优先级建议

### 高优先级（必须先修复）
1. **Python 模块结构问题** - 这是最简单的修复，可以先验证框架是否正常工作
2. **JavaScript 环境配置** - Node.js 项目通常最容易配置

### 中优先级
3. **Go 项目编译** - Go 编译相对简单
4. **C# 项目编译** - 需要 .NET 环境

### 低优先级（较复杂）
5. **Java 项目配置** - 需要 Maven 和 JDK
6. **Rust 项目编译** - 编译时间较长
7. **C/C++ 项目编译** - 需要配置 MSVC 和 GmSSL 库

---

## 四、逐步验证方法

修复每个语言后，按以下步骤验证：

1. **单独运行加密测试**:
   ```bash
   python testcase/{language}_interop_test.py
   ```

2. **检查输出目录**:
   ```bash
   dir testcase/results/{language}_encrypt
   ```
   应包含 5 个测试用例的 JSON 文件

3. **单独运行验证测试**:
   ```bash
   python testcase/{language}_verify_decrypt_test.py
   ```

4. **确认结果**:
   检查 `testcase/results/{language}_verify/summary.json`

---

## 五、环境检查清单

- [ ] JDK 21: `H:\Programs\Java\jdk-21.0.1+12\bin\java -version`
- [ ] Maven: `mvn -version`
- [ ] Python 3.12: `H:\Programs\Python3\python.exe --version`
- [ ] Node.js: `node --version`
- [ ] Go: `go version`
- [ ] .NET SDK: `dotnet --version`
- [ ] Rust: `cargo --version`
- [ ] MSVC: `cl` 命令是否可用

---

**注意**: 修复完所有加密测试后，重新运行 `python testcase/run_all_interop_tests.py` 获取完整测试结果。