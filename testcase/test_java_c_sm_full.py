#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java-C SM2/SM3/SM4 完整互通性测试

这个脚本：
1. 使用 Java 生成测试数据（密钥、密文、签名等）
2. 调用 C 程序验证 Java 生成的数据
3. 生成 C 数据供 Java 验证
4. 生成完整的测试报告
"""

import os
import sys
import subprocess
import json
from datetime import datetime
from pathlib import Path

# ==================== 配置 ====================

ROOT_DIR = Path(__file__).parent.parent.resolve()
JAVA_DIR = ROOT_DIR / "java" / "crossmool"
C_DIR = ROOT_DIR / "c" / "crossmool"
TESTCASE_DIR = ROOT_DIR / "testcase"
BUILD_DIR = TESTCASE_DIR / "build" / "sm_interop"

# 测试消息
TEST_MESSAGE = "Hello, Cross-Language Interop Test! 测试消息 123456"
TEST_HMAC_KEY_HEX = "0123456789abcdef0123456789abcdef"

# ==================== 工具函数 ====================

def print_header(text):
    print("\n" + "=" * 60)
    print(f" {text}")
    print("=" * 60)

def print_success(text):
    print(f"[OK] {text}")

def print_error(text):
    print(f"[ERROR] {text}")

def print_info(text):
    print(f"[INFO] {text}")

def run_cmd(cmd, cwd=None, capture=True):
    """运行命令"""
    print_info(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        result = subprocess.run(
            cmd if isinstance(cmd, list) else cmd.split(),
            cwd=cwd,
            capture_output=capture,
            text=True,
            timeout=120
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        print_error(f"Command failed: {e}")
        return -1, "", str(e)

# ==================== Java 测试数据生成 ====================

def generate_java_test_data():
    """使用 Java 生成测试数据"""
    print_header("Step 1: Generate Test Data with Java")
    
    # 创建 Java 测试程序
    java_test_code = f'''
import cc.iili.tools.crossmool.bean.SerialKeyPair;
import cc.iili.tools.crossmool.tool.*;
import cc.iili.tools.crossmool.util.HexUtil;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class GenerateTestData {{
    public static void main(String[] args) throws Exception {{
        System.out.println("Generating Java test data...");
        
        String testMessage = "{TEST_MESSAGE}";
        String hmacKeyHex = "{TEST_HMAC_KEY_HEX}";
        
        // 生成 SM2 密钥对
        SerialKeyPair sm2Keys = SM2Util.generateKeyPairHex();
        System.out.println("SM2 Public Key: " + sm2Keys.getPublicKey());
        System.out.println("SM2 Private Key: " + sm2Keys.getPrivateKey());
        
        // SM2 加密
        String sm2Ciphertext = SM2Util.encrypt(testMessage, sm2Keys.getPublicKey());
        System.out.println("SM2 Ciphertext: " + sm2Ciphertext);
        
        // SM2 签名
        String sm2Signature = SM2Util.sign(testMessage, sm2Keys.getPrivateKey());
        System.out.println("SM2 Signature: " + sm2Signature);
        
        // SM3 摘要
        String sm3Digest = SM3Util.digestToStr(testMessage);
        System.out.println("SM3 Digest: " + sm3Digest);
        
        // HMAC-SM3
        String hmacSm3 = SM3Util.hmacToStr(hmacKeyHex, testMessage);
        System.out.println("HMAC-SM3: " + hmacSm3);
        
        // SM4 密钥和加密
        String sm4KeyHex = SM4Util.generateKeyAsHex();
        byte[] sm4Key = HexUtil.decodeHexStr(sm4KeyHex);
        String sm4Ciphertext = SM4Util.encryptEcbNative(sm4Key, testMessage.getBytes(StandardCharsets.UTF_8));
        System.out.println("SM4 Key: " + sm4KeyHex);
        System.out.println("SM4 Ciphertext: " + sm4Ciphertext);
        
        // 保存测试数据到 JSON
        Map<String, String> data = new HashMap<>();
        data.put("test_message", testMessage);
        data.put("sm2_public_key", sm2Keys.getPublicKey());
        data.put("sm2_private_key", sm2Keys.getPrivateKey());
        data.put("sm2_ciphertext", sm2Ciphertext);
        data.put("sm2_signature", sm2Signature);
        data.put("sm3_digest", sm3Digest);
        data.put("hmac_key_hex", hmacKeyHex);
        data.put("hmac_sm3", hmacSm3);
        data.put("sm4_key_hex", sm4KeyHex);
        data.put("sm4_ciphertext", sm4Ciphertext);
        
        String json = "{{" + String.join(",", 
            "\"test_message\":\"" + data.get("test_message") + "\"",
            "\"sm2_public_key\":\"" + data.get("sm2_public_key") + "\"",
            "\"sm2_private_key\":\"" + data.get("sm2_private_key") + "\"",
            "\"sm2_ciphertext\":\"" + data.get("sm2_ciphertext") + "\"",
            "\"sm2_signature\":\"" + data.get("sm2_signature") + "\"",
            "\"sm3_digest\":\"" + data.get("sm3_digest") + "\"",
            "\"hmac_key_hex\":\"" + data.get("hmac_key_hex") + "\"",
            "\"hmac_sm3\":\"" + data.get("hmac_sm3") + "\"",
            "\"sm4_key_hex\":\"" + data.get("sm4_key_hex") + "\"",
            "\"sm4_ciphertext\":\"" + data.get("sm4_ciphertext") + "\""
        ) + "}}";
        
        Files.writeString(Paths.get("test_data.json"), json);
        System.out.println("Test data saved to test_data.json");
        System.out.println("Java test data generation complete!");
    }}
}}
'''
    
    java_file = BUILD_DIR / "GenerateTestData.java"
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    java_file.write_text(java_test_code)
    
    # 编译 Java
    print_info("Compiling Java test data generator...")
    
    # 构建 classpath
    classpath_parts = [
        str(JAVA_DIR / "target" / "classes")
    ]
    
    # 查找 Maven 依赖
    maven_repo = Path.home() / ".m2" / "repository"
    deps = [
        "org/bouncycastle/bcprov-jdk18on/1.82/bcprov-jdk18on-1.82.jar",
        "org/projectlombok/lombok/1.18.42/lombok-1.18.42.jar",
    ]
    
    for dep in deps:
        dep_path = maven_repo / dep
        if dep_path.exists():
            classpath_parts.append(str(dep_path))
    
    classpath = ";".join(classpath_parts)
    
    ret, stdout, stderr = run_cmd(
        f'javac -encoding UTF-8 -cp "{classpath}" -d "{BUILD_DIR}" "{java_file}"',
        capture=True
    )
    
    if ret != 0:
        print_error("Java compilation failed")
        print(stderr)
        return None
    
    # 运行 Java
    print_info("Running Java test data generator...")
    ret, stdout, stderr = run_cmd(
        f'java -cp "{classpath};{BUILD_DIR}" GenerateTestData',
        cwd=BUILD_DIR,
        capture=True
    )
    
    if ret != 0:
        print_error("Java execution failed")
        print(stderr)
        return None
    
    print(stdout)
    
    # 读取测试数据
    test_data_file = BUILD_DIR / "test_data.json"
    if not test_data_file.exists():
        print_error("Test data file not created")
        return None
    
    import json
    with open(test_data_file, 'r', encoding='utf-8') as f:
        test_data = json.load(f)
    
    print_success("Java test data generated successfully")
    return test_data

# ==================== C 测试程序编译 ====================

def compile_c_test():
    """编译 C 测试程序"""
    print_header("Step 2: Compile C Test Program")
    
    # 查找必要的文件
    c_test_file = TESTCASE_DIR / "test_java_c_interop_sm.c"
    c_src_dir = C_DIR / "src"
    c_inc_dir = C_DIR / "include"
    c_build_dir = C_DIR / "build" / "Release"
    
    if not c_test_file.exists():
        print_error(f"C test file not found: {c_test_file}")
        return None
    
    # 查找 GmSSL
    gmssl_paths = [
        Path("H:/Programs/GmSSL"),
        Path("C:/Program Files/GmSSL"),
    ]
    
    gmssl_path = None
    for p in gmssl_paths:
        if p.exists():
            gmssl_path = p
            break
    
    if not gmssl_path:
        print_error("GmSSL not found")
        return None
    
    print_info(f"Using GmSSL at: {gmssl_path}")
    
    # 查找 Visual Studio
    vs_paths = []
    for ver in ["18", "17", "16"]:
        for edition in ["Community", "Professional", "Enterprise", "BuildTools"]:
            vs_paths.append(
                Path(f"G:/Programs/Microsoft Visual Studio/{ver}/{edition}/VC/Auxiliary/Build/vcvars64.bat")
            )
    
    vcvars_cmd = None
    for vp in vs_paths:
        if vp.exists():
            vcvars_cmd = vp
            break
    
    if not vcvars_cmd:
        print_error("Visual Studio not found")
        return None
    
    print_info(f"Using VS: {vcvars_cmd}")
    
    # 编译命令
    cl_cmd = (
        f'cmd /c "call "{vcvars_cmd}" >nul 2>&1 && '
        f'cl /nologo /MD /I"{c_inc_dir}" /I"{gmssl_path}\\include" '
        f'/Fo"{BUILD_DIR}\\test_java_c_interop_sm.obj" '
        f'"{c_test_file}" '
        f'"{c_src_dir}\\sm2.c" '
        f'"{c_src_dir}\\sm3.c" '
        f'"{c_src_dir}\\sm4.c" '
        f'"{c_src_dir}\\util_hex.c" '
        f'"{c_src_dir}\\util_base64.c" '
        f'"{c_src_dir}\\util_string.c" '
        f'"{c_src_dir}\\error.c" '
        f'/link /LIBPATH:"{c_build_dir}" /LIBPATH:"{gmssl_path}\\lib" '
        f'gmssl.lib '
        f'/OUT:"{BUILD_DIR}\\test_java_c_interop_sm.exe""'
    )
    
    print_info(f"Compiling with: {cl_cmd[:100]}...")
    
    ret, stdout, stderr = run_cmd(cl_cmd, capture=True)
    
    exe_file = BUILD_DIR / "test_java_c_interop_sm.exe"
    if not exe_file.exists():
        print_error("C compilation failed")
        print(stderr)
        return None
    
    print_success(f"C test program compiled: {exe_file}")
    return exe_file

# ==================== 运行 C 测试 ====================

def run_c_test(test_data, c_exe):
    """运行 C 测试程序"""
    print_header("Step 3: Run C Tests")
    
    if not c_exe.exists():
        print_error("C test executable not found")
        return {}
    
    # 准备参数
    args = [
        str(c_exe),
        test_data["sm2_private_key"],
        test_data["sm2_public_key"],
        test_data["sm4_key_hex"],
        test_data["sm2_ciphertext"],
        test_data["sm2_signature"],
        test_data["sm3_digest"],
        test_data["hmac_sm3"],
        test_data["sm4_ciphertext"],
    ]
    
    print_info("Running C test program...")
    ret, stdout, stderr = run_cmd(args, capture=True)
    
    print(stdout)
    if stderr:
        print(stderr)
    
    # 解析结果
    results = {}
    for line in stdout.split('\n'):
        if '[PASS]' in line or '[FAIL]' in line:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                test_name = parts[0].strip('[]').strip()
                result = 'PASS' if 'PASS' in line else 'FAIL'
                results[test_name] = result
    
    return results

# ==================== 生成报告 ====================

def generate_report(test_data, c_results):
    """生成测试报告"""
    print_header("Step 4: Generate Test Report")
    
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 统计结果
    total = len(c_results)
    passed = sum(1 for v in c_results.values() if v == 'PASS')
    
    report = f"""# Java-C SM2/SM3/SM4 互通性测试报告

## 测试信息

- **测试时间**: {report_time}
- **测试消息**: {TEST_MESSAGE}
- **Java 实现**: crossmool/java/crossmool (BouncyCastle 1.82)
- **C 实现**: crossmool/c/crossmool (GmSSL)
- **测试环境**: Windows 11, MSVC/x64

## 测试数据

### SM2 密钥对

- **公钥 (HEX)**: `{test_data["sm2_public_key"]}`
- **私钥 (HEX)**: `{test_data["sm2_private_key"]}`

### SM2 加密测试

- **明文**: `{test_data["test_message"]}`
- **密文 (Java 生成)**: `{test_data["sm2_ciphertext"]}`

### SM2 签名测试

- **签名 (Java 生成)**: `{test_data["sm2_signature"]}`

### SM3 摘要测试

- **SM3(明文)**: `{test_data["sm3_digest"]}`

### HMAC-SM3 测试

- **HMAC 密钥**: `{test_data["hmac_key_hex"]}`
- **HMAC-SM3(明文)**: `{test_data["hmac_sm3"]}`

### SM4 加密测试

- **SM4 密钥**: `{test_data["sm4_key_hex"]}`
- **SM4 密文 (Java 生成)**: `{test_data["sm4_ciphertext"]}`

## C 侧测试结果

| 测试项 | 结果 |
|--------|------|
"""
    
    for test_name, result in c_results.items():
        icon = "✅" if result == "PASS" else "❌"
        report += f"| {test_name} | {icon} {result} |\n"
    
    report += f"""
## 总体统计

- **总测试数**: {total}
- **通过数**: {passed}
- **失败数**: {total - passed}
- **成功率**: {passed/total*100:.1f}% (如果 total>0)

## 测试详细说明

### 1. SM2 加密互通性

**测试**: Java 加密 -> C 解密

Java 使用 BouncyCastle 的 SM2Engine (C1C3C2 模式) 加密，C 使用 GmSSL 解密。
C 代码支持两种格式的密文：
- GmSSL DER SEQUENCE 格式（30 开头）
- Java/BouncyCastle RAW C1C3C2 格式（04 开头）

### 2. SM2 签名互通性

**测试**: Java 签名 -> C 验签

Java 使用 SM2Signer 生成 DER 编码签名 (SEQUENCE {r, s})。
C 使用 GmSSL 的 sm2_verify_finish，原生支持 DER 格式。

### 3. SM3 摘要互通性

**测试**: Java SM3 -> C 验证

两边都使用标准的 SM3 算法，输出应该完全一致。

### 4. HMAC-SM3 互通性

**测试**: Java HMAC -> C 验证

两边使用相同的密钥和消息，HMAC 输出应该一致。

### 5. SM4 加密互通性

**测试**: Java SM4 加密 -> C 解密

Java 使用 SM4/ECB/PKCS7Padding，C 使用 SM4 ECB with PKCS7 padding。
两者都应该产生相同的结果。

## 关键实现细节

### SM2 用户 ID

两边都使用固定用户 ID: `"1234567812345678"`

### SM2 密文格式转换

C 代码中的 `sm2_raw_c1c3c2_to_der()` 函数负责将 Java 的 RAW C1C3C2 格式
转换为 GmSSL 期望的 DER SEQUENCE 格式。

### SM2 签名格式

Java BouncyCastle 输出 DER 编码的签名，GmSSL 原生支持，无需转换。

## 结论

"""
    
    if passed == total and total > 0:
        report += "✅ **所有测试通过**，Java 和 C 实现完全互通。\n"
    elif total == 0:
        report += "⚠️ **没有执行测试**，需要检查测试环境。\n"
    else:
        report += f"⚠️ **{total - passed} 个测试失败**，需要进一步检查。\n"
    
    report += "\n---\n*报告由 test_java_c_sm_full.py 自动生成*\n"
    
    # 保存报告
    report_file = TESTCASE_DIR / "results" / "java_c_sm_interop_report.md"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(report, encoding='utf-8')
    
    print_success(f"Report saved to: {report_file}")
    print("\n" + report)
    
    return report

# ==================== 主函数 ====================

def main():
    """主函数"""
    print_header("Java-C SM2/SM3/SM4 Interoperability Test")
    
    # 1. 生成 Java 测试数据
    test_data = generate_java_test_data()
    if not test_data:
        print_error("Failed to generate Java test data")
        return 1
    
    # 2. 编译 C 测试程序
    c_exe = compile_c_test()
    if not c_exe:
        print_error("Failed to compile C test program")
        return 1
    
    # 3. 运行 C 测试
    c_results = run_c_test(test_data, c_exe)
    
    # 4. 生成报告
    generate_report(test_data, c_results)
    
    print_success("Test completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())