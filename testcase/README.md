# Java-Go SM2/SM3/SM4 互通性测试

本目录包含 Java 和 Go 语言实现的 SM2/SM3/SM4 国密算法互通性测试。

## 测试文件

- `JavaGoInteropTest.java` - Java 测试数据生成器
- `run_java_go_interop_test.sh` - 一键运行所有测试的脚本
- `Java-Go-interop-test-report.md` - 详细测试报告
- `java_go_test_output.txt` - Java 测试输出（运行后生成）
- `go_unit_test_output.txt` - Go 单元测试输出（运行后生成）
- `go_verify_output.txt` - Go 验证输出（运行后生成）

## 快速开始

### 方式一：运行测试脚本（推荐）

```bash
cd testcase
bash run_java_go_interop_test.sh
```

脚本将自动执行以下步骤：
1. 编译 Java 项目
2. 运行 Java 测试数据生成器
3. 运行 Go 单元测试
4. 运行 Go 验证程序
5. 生成测试报告

### 方式二：手动运行

#### 1. 编译并运行 Java 测试

```bash
cd java/crossmool
mvn clean compile
javac -cp "target/classes;$(cat cp.txt)" -d target/classes ../../testcase/JavaGoInteropTest.java
java -cp "target/classes;$(cat cp.txt)" JavaGoInteropTest
```

#### 2. 运行 Go 单元测试

```bash
cd golang/crossmool
go mod tidy
go test -v -run "SM4|SM2|SM3"
```

#### 3. 运行 Go 验证程序

```bash
cd golang/verify
go mod tidy
go run verify_java_interop.go
```

## 测试结果

### 测试摘要

| 算法 | 测试项 | Hex 编码 | Base64 编码 | 结果 |
|------|--------|----------|-------------|------|
| **SM2** | 加密/解密 | ✅ 通过 | ✅ 通过 | 完全互通 |
| **SM2** | 签名/验签 | ✅ 通过 | ✅ 通过 | 完全互通 |
| **SM3** | 摘要计算 | ✅ 通过 | ✅ 通过 | 完全互通 |
| **HMAC-SM3** | MAC 计算 | ✅ 通过 | ✅ 通过 | 完全互通 |
| **SM4-GCM** | 加密/解密 | ✅ 通过 | ✅ 通过 | 完全互通 |

**总计**: 10/10 测试项通过，互通性测试成功！

### 详细测试报告

完整测试报告请查看：`Java-Go-interop-test-report.md`

## 技术要点

### SM2
- 曲线：sm2p256v1
- 加密模式：C1C3C2
- 签名 USER_ID: `1234567812345678`
- 密钥格式：X.509 公钥 / PKCS#8 私钥（DER 编码）

### SM3
- 摘要长度：32 字节
- 完全兼容

### HMAC-SM3
- 支持 Hex/Base64 密钥格式
- 完全兼容

### SM4-GCM
- IV 长度：12 字节
- Tag 长度：16 字节
- 密文格式：IV + Ciphertext + Tag

## 编码格式支持

- ✅ Hex 编码：Java 和 Go 均支持十六进制字符串
- ✅ Base64 编码：Java 和 Go 均支持 Base64 字符串
- ✅ 自动检测：两者都支持自动检测输入字符串的编码格式（Hex 优先）

## 结论

✅ **所有测试通过！** Java 和 Go 的 SM2/SM3/SM4 实现完全互通。

- Go 实现可以直接替换 Java 实现，无需修改接口
- 可以在混合语言环境中使用（如 Java 加密，Go 解密）
- 支持 Hex 和 Base64 两种编码格式，便于不同场景使用