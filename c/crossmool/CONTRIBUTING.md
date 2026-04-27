# 贡献指南

欢迎为 crossmool-c 项目做出贡献！

## 开发环境设置

### 1. 安装依赖

```bash
# 安装 vcpkg
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh  # Linux/macOS
.\bootstrap-vcpkg.bat  # Windows

# 安装 GmSSL
vcpkg install gmssl
```

### 2. 构建项目

```bash
# Windows
build_windows.bat

# Linux/macOS
chmod +x build_linux.sh
./build_linux.sh
```

## 代码规范

### C 语言风格

- 使用 4 空格缩进
- 函数名使用 `crossmool_*` 前缀
- 宏定义使用大写字母和下划线
- 遵循 C20 标准

### 命名规范

- 文件：小写字母和下划线（如 `sm2_util.c`）
- 函数：`crossmool_模块_功能`（如 `crossmool_sm2_encrypt`）
- 常量：大写字母和下划线（如 `CROSSMOOL_SM2_MAX_LEN`）
- 结构体：`crossmool_*_t`（如 `crossmool_sm2_keypair_t`）

### 注释规范

```c
/**
 * 函数描述
 * 
 * @param param1 参数描述
 * @param param2 参数描述
 * @return 返回值描述
 */
int crossmool_sm2_encrypt(...) {
    // 实现代码
}
```

## 提交规范

### Commit Message 格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

#### 类型 (type)
- `feat`: 新功能
- `fix`: 修复 bug
- `docs`: 文档更新
- `style`: 代码格式调整
- `refactor`: 重构
- `test`: 测试相关
- `chore`: 构建/工具相关

#### 示例

```
feat(sm2): 添加 SM2 加密 API

实现了 SM2 加密功能，支持 C1C3C2 格式

- 支持 byte[] 输入输出
- 支持 UTF-8 字符集
- 与 Java 版本完全互通
```

## 测试

### 运行单元测试

```bash
cd build
ctest -C Release --output-on-failure
```

### 运行互通性测试

```bash
ctest -R interop -C Release --output-on-failure
```

## 代码审查

所有贡献需要通过代码审查：

1. 代码符合项目规范
2. 所有测试通过
3. 有完整的文档和注释
4. 与现有实现保持互通

## 报告问题

提交 Issue 时请包含：

- 问题描述
- 复现步骤
- 预期行为
- 实际行为
- 环境信息（操作系统、编译器版本、GmSSL 版本）

## 联系方式

- GitHub Issues
- 项目邮箱：crossmool@example.com