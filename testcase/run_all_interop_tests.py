#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

"""
跨语言 SM2 加密签名互通性测试主框架

功能：
1. 协调 8 种语言（Java/C/C++/C#/Go/JavaScript/Python/Rust）的加密签名和解密验签测试
2. 执行 8 组交叉测试（每种语言作为加密端，其他 7 种语言作为验证端）
3. 生成包含详细错误信息和修改意见的完整测试报告

测试矩阵：
- 加密端：8 种语言 × 5 个测试用例 = 40 组加密结果
- 验证端：8 种语言 × 7 种其他语言 × 5 个测试用例 = 280 组验证测试
- 总计：320 组测试

使用方法：
    python testcase/run_all_interop_tests.py [--encrypt-only] [--verify-only] [--language LANG]
    
选项：
    --encrypt-only    仅执行加密测试
    --verify-only     仅执行验证测试
    --language LANG   指定语言（java/c/cpp/csharp/golang/javascript/python/rust）
"""

import json
import os
import sys
import subprocess
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

# ============================================================================
# 配置常量
# ============================================================================

class Language(Enum):
    """支持的语言枚举"""
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    GOLANG = "golang"
    JAVASCRIPT = "javascript"
    PYTHON = "python"
    RUST = "rust"
    
    def __str__(self):
        return self.value

# 所有支持的语言
ALL_LANGUAGES = [
    Language.JAVA, Language.C, Language.CPP, Language.CSHARP,
    Language.GOLANG, Language.JAVASCRIPT, Language.PYTHON, Language.RUST
]

# 环境配置
ENV_CONFIG = {
    "JDK_HOME": r"H:\Programs\Java\jdk-21.0.1+12",
    "PYTHON_HOME": r"H:\Programs\Python3",
    "MSVC_DIR": r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
    "GO_HOME": r"H:\Programs\Go",
    "DOTNET_HOME": r"C:\Program Files\dotnet",
    "NPM_HOME": r"H:\Programs\nodejs",
}

# 测试数据路径
TEST_DATA_FILE = "testcase/test_data.json"
KEYS_BASE_DIR = "testcase/keys"
RESULTS_BASE_DIR = "testcase/results"
REPORT_FILE = "testcase/results/interop_test_report.json"
REPORT_MD_FILE = "testcase/results/interop_test_report.md"

# 各语言的可执行文件/脚本路径
EXECUTABLE_PATHS = {
    Language.JAVA: {
        "jar": "java/crossmool/target/crossmool-1.1.0.jar",
        "classpath": "java/crossmool/classpath.txt",
        "script": "testcase/java_interop_test.py",
    },
    Language.C: {
        "dll": "c/crossmool/build_msvc/Release/crossmool.dll",
        "exe": "c/crossmool/build_msvc/examples/Release/example_interop.exe",
        "script": "testcase/c_interop_test.py",
    },
    Language.CPP: {
        "exe": "cpp/crossmool/build/bin/Release/interoperability_test.exe",
        "script": "testcase/cpp_interop_test.py",
    },
    Language.CSHARP: {
        "dll": "csharp/crossmool/src/Crossmool.Crypto/bin/Release/net8.0/Crossmool.Crypto.dll",
        "script": "testcase/csharp_interop_test.py",
    },
    Language.GOLANG: {
        "exe": "golang/crossmool/interop_test.exe",
        "script": "testcase/golang_interop_test.py",
    },
    Language.JAVASCRIPT: {
        "dist": "javascript/crossmool/dist",
        "script": "testcase/javascript_interop_test.py",
    },
    Language.PYTHON: {
        "src": "python/crossmool/src/crossmool",
        "script": "testcase/python_interop_test.py",
    },
    Language.RUST: {
        "exe": "rust/crossmool/target/release/interop_test.exe",
        "script": "testcase/rust_interop_test.py",
    },
}

# ============================================================================
# 数据类定义
# ============================================================================

@dataclass
class TestCase:
    """测试用例"""
    id: int
    name: str
    plaintext: str

@dataclass
class KeyPair:
    """密钥对"""
    encryption_public_key_hex: str
    encryption_public_key_b64: str
    signature_private_key_hex: str
    signature_private_key_b64: str
    encryption_private_key_hex: Optional[str] = None
    encryption_private_key_b64: Optional[str] = None
    signature_public_key_hex: Optional[str] = None
    signature_public_key_b64: Optional[str] = None

@dataclass
class EncryptResult:
    """加密结果"""
    test_case_id: int
    test_case_name: str
    plaintext: str
    ciphertext_hex: str
    signature_hex: str
    language: str
    success: bool
    error: Optional[str] = None
    duration_ms: int = 0

@dataclass
class VerifyResult:
    """验证结果"""
    encrypt_language: str
    verify_language: str
    test_case_id: int
    test_case_name: str
    success: bool
    decrypted_text: Optional[str] = None
    plaintext_matched: bool = False
    signature_valid: bool = False
    error: Optional[str] = None
    suggestion: Optional[str] = None
    duration_ms: int = 0

@dataclass
class TestReport:
    """测试报告"""
    start_time: str
    end_time: Optional[str] = None
    total_duration_seconds: float = 0.0
    languages_tested: List[str] = field(default_factory=list)
    encrypt_results: List[Dict] = field(default_factory=list)
    verify_results: List[Dict] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    errors: List[Dict] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

# ============================================================================
# 工具函数
# ============================================================================

def load_test_data() -> List[TestCase]:
    """加载测试数据"""
    with open(TEST_DATA_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    return [
        TestCase(id=tc["id"], name=tc["name"], plaintext=tc["plaintext"])
        for tc in data["test_cases"]
    ]

def load_keys(language: Language) -> KeyPair:
    """加载指定语言的密钥"""
    keys_file = Path(KEYS_BASE_DIR) / language.value / "keys.json"
    
    if not keys_file.exists():
        raise FileNotFoundError(f"密钥文件不存在：{keys_file}")
    
    with open(keys_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    return KeyPair(
        encryption_public_key_hex=data["encryption_public_key"]["hex"],
        encryption_public_key_b64=data["encryption_public_key"]["base64"],
        signature_private_key_hex=data["signature_private_key"]["hex"],
        signature_private_key_b64=data["signature_private_key"]["base64"],
        encryption_private_key_hex=data.get("encryption_private_key", {}).get("hex"),
        encryption_private_key_b64=data.get("encryption_private_key", {}).get("base64"),
        signature_public_key_hex=data.get("signature_public_key", {}).get("hex"),
        signature_public_key_b64=data.get("signature_public_key", {}).get("base64"),
    )

def save_json_file(file_path: str, data: Any) -> None:
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_python_script(script_path: str, *args) -> Tuple[int, str, str]:
    """运行 Python 脚本"""
    python_exe = os.path.join(ENV_CONFIG["PYTHON_HOME"], "python.exe")
    cmd = [python_exe, script_path] + list(args)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            encoding='utf-8'
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "脚本执行超时"
    except Exception as e:
        return -1, "", str(e)

def format_duration(seconds: float) -> str:
    """格式化持续时间"""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}分{secs:.0f}秒"

# ============================================================================
# 加密测试函数
# ============================================================================

def run_java_encrypt_test(test_cases: List[TestCase], keys: KeyPair) -> List[EncryptResult]:
    """运行 Java 加密测试"""
    results = []
    script_path = EXECUTABLE_PATHS[Language.JAVA]["script"]
    
    if not os.path.exists(script_path):
        print(f"  [!] Java 测试脚本不存在：{script_path}")
        return results
    
    print(f"  运行 Java 加密测试...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] Java 加密测试失败：{stderr}")
        return results
    
    # 读取结果
    output_dir = "testcase/results/java_encrypt"
    for tc in test_cases:
        result_file = Path(output_dir) / f"test_{tc.id}_{tc.name}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results.append(EncryptResult(
                test_case_id=tc.id,
                test_case_name=tc.name,
                plaintext=tc.plaintext,
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                language="java",
                success=True
            ))
    
    return results

def run_c_encrypt_test(test_cases: List[TestCase], keys: KeyPair) -> List[EncryptResult]:
    """运行 C 语言加密测试"""
    results = []
    script_path = EXECUTABLE_PATHS[Language.C]["script"]
    
    if not os.path.exists(script_path):
        print(f"  [!] C 语言测试脚本不存在：{script_path}")
        return results
    
    print(f"  运行 C 语言加密测试...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] C 语言加密测试失败：{stderr}")
        return results
    
    # 读取结果
    output_dir = "testcase/results/c_encrypt"
    for tc in test_cases:
        result_file = Path(output_dir) / f"test_{tc.id}_{tc.name}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results.append(EncryptResult(
                test_case_id=tc.id,
                test_case_name=tc.name,
                plaintext=tc.plaintext,
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                language="c",
                success=True
            ))
    
    return results

def run_cpp_encrypt_test(test_cases: List[TestCase], keys: KeyPair) -> List[EncryptResult]:
    """运行 C++ 加密测试"""
    results = []
    script_path = EXECUTABLE_PATHS[Language.CPP]["script"]
    
    if not os.path.exists(script_path):
        print(f"  [!] C++ 测试脚本不存在：{script_path}")
        return results
    
    print(f"  运行 C++ 加密测试...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] C++ 加密测试失败：{stderr}")
        return results
    
    # 读取结果
    output_dir = "testcase/results/cpp_encrypt"
    for tc in test_cases:
        result_file = Path(output_dir) / f"test_{tc.id}_{tc.name}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results.append(EncryptResult(
                test_case_id=tc.id,
                test_case_name=tc.name,
                plaintext=tc.plaintext,
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                language="cpp",
                success=True
            ))
    
    return results

def run_csharp_encrypt_test(test_cases: List[TestCase], keys: KeyPair) -> List[EncryptResult]:
    """运行 C# 加密测试"""
    results = []
    script_path = EXECUTABLE_PATHS[Language.CSHARP]["script"]
    
    if not os.path.exists(script_path):
        print(f"  [!] C# 测试脚本不存在：{script_path}")
        return results
    
    print(f"  运行 C# 加密测试...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] C# 加密测试失败：{stderr}")
        return results
    
    # 读取结果
    output_dir = "testcase/results/csharp_encrypt"
    for tc in test_cases:
        result_file = Path(output_dir) / f"test_{tc.id}_{tc.name}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results.append(EncryptResult(
                test_case_id=tc.id,
                test_case_name=tc.name,
                plaintext=tc.plaintext,
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                language="csharp",
                success=True
            ))
    
    return results

def run_golang_encrypt_test(test_cases: List[TestCase], keys: KeyPair) -> List[EncryptResult]:
    """运行 Go 加密测试"""
    results = []
    script_path = EXECUTABLE_PATHS[Language.GOLANG]["script"]
    
    if not os.path.exists(script_path):
        print(f"  [!] Go 测试脚本不存在：{script_path}")
        return results
    
    print(f"  运行 Go 加密测试...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] Go 加密测试失败：{stderr}")
        return results
    
    # 读取结果
    output_dir = "testcase/results/golang_encrypt"
    for tc in test_cases:
        result_file = Path(output_dir) / f"test_{tc.id}_{tc.name}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results.append(EncryptResult(
                test_case_id=tc.id,
                test_case_name=tc.name,
                plaintext=tc.plaintext,
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                language="golang",
                success=True
            ))
    
    return results

def run_javascript_encrypt_test(test_cases: List[TestCase], keys: KeyPair) -> List[EncryptResult]:
    """运行 JavaScript 加密测试"""
    results = []
    script_path = EXECUTABLE_PATHS[Language.JAVASCRIPT]["script"]
    
    if not os.path.exists(script_path):
        print(f"  [!] JavaScript 测试脚本不存在：{script_path}")
        return results
    
    print(f"  运行 JavaScript 加密测试...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] JavaScript 加密测试失败：{stderr}")
        return results
    
    # 读取结果
    output_dir = "testcase/results/javascript_encrypt"
    for tc in test_cases:
        result_file = Path(output_dir) / f"test_{tc.id}_{tc.name}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results.append(EncryptResult(
                test_case_id=tc.id,
                test_case_name=tc.name,
                plaintext=tc.plaintext,
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                language="javascript",
                success=True
            ))
    
    return results

def run_python_encrypt_test(test_cases: List[TestCase], keys: KeyPair) -> List[EncryptResult]:
    """运行 Python 加密测试"""
    results = []
    script_path = EXECUTABLE_PATHS[Language.PYTHON]["script"]
    
    if not os.path.exists(script_path):
        print(f"  [!] Python 测试脚本不存在：{script_path}")
        return results
    
    print(f"  运行 Python 加密测试...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] Python 加密测试失败：{stderr}")
        return results
    
    # 读取结果
    output_dir = "testcase/results/python_encrypt"
    for tc in test_cases:
        result_file = Path(output_dir) / f"test_{tc.id}_{tc.name}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results.append(EncryptResult(
                test_case_id=tc.id,
                test_case_name=tc.name,
                plaintext=tc.plaintext,
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                language="python",
                success=True
            ))
    
    return results

def run_rust_encrypt_test(test_cases: List[TestCase], keys: KeyPair) -> List[EncryptResult]:
    """运行 Rust 加密测试"""
    results = []
    script_path = EXECUTABLE_PATHS[Language.RUST]["script"]
    
    if not os.path.exists(script_path):
        print(f"  [!] Rust 测试脚本不存在：{script_path}")
        return results
    
    print(f"  运行 Rust 加密测试...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] Rust 加密测试失败：{stderr}")
        return results
    
    # 读取结果
    output_dir = "testcase/results/rust_encrypt"
    for tc in test_cases:
        result_file = Path(output_dir) / f"test_{tc.id}_{tc.name}.json"
        if result_file.exists():
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            results.append(EncryptResult(
                test_case_id=tc.id,
                test_case_name=tc.name,
                plaintext=tc.plaintext,
                ciphertext_hex=data.get("ciphertext_hex", ""),
                signature_hex=data.get("signature_hex", ""),
                language="rust",
                success=True
            ))
    
    return results

# ============================================================================
# 验证测试函数
# ============================================================================

def run_java_verify_test(encrypt_results: List[EncryptResult], keys: KeyPair) -> List[VerifyResult]:
    """运行 Java 验证测试"""
    results = []
    script_path = "testcase/java_verify_decrypt_test.py"
    
    if not os.path.exists(script_path):
        print(f"  [!] Java 验证测试脚本不存在：{script_path}")
        # 返回待实现结果
        for enc_result in encrypt_results:
            if enc_result.language == "java":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="java",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本不存在：{script_path}",
                suggestion="请检查 java_verify_decrypt_test.py 脚本"
            ))
        return results
    
    print(f"  运行 Java 验证测试脚本...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] Java 验证测试脚本执行失败：{stderr[:200]}")
        # 返回失败结果
        for enc_result in encrypt_results:
            if enc_result.language == "java":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="java",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本执行失败：{stderr[:100]}",
                suggestion="检查 Java 环境和 JAR 文件配置"
            ))
        return results
    
    # 读取验证结果
    output_dir = "testcase/results/java_verify"
    summary_file = Path(output_dir) / "summary.json"
    
    if summary_file.exists():
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_data = json.load(f)
        
        # 从各语言的验证结果中提取详细信息
        for lang_name, lang_data in summary_data.get("languages", {}).items():
            if lang_name == "java":
                continue  # 跳过同语言验证
            
            for result_entry in lang_data.get("results", []):
                test_id = result_entry.get("test_case_id", 0)
                test_name = result_entry.get("test_case_name", "unknown")
                status = result_entry.get("status", "failed")
                
                # 查找对应的加密结果以获取明文
                expected_plaintext = ""
                for enc_res in encrypt_results:
                    if enc_res.test_case_id == test_id and enc_res.language == lang_name:
                        expected_plaintext = enc_res.plaintext
                        break
                
                if status == "success":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="java",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=True,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=True,
                        signature_valid=True
                    ))
                elif status == "mismatch":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="java",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=False,
                        signature_valid=True,
                        error="解密结果与原始明文不匹配",
                        suggestion=f"期望：{expected_plaintext[:50]}..., 实际：{result_entry.get('decrypted_text', '')[:50]}..."
                    ))
                else:
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="java",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        error=result_entry.get("error", "验签或解密失败"),
                        suggestion="检查密钥格式或 SM2 实现"
                    ))
    
    return results

def run_c_verify_test(encrypt_results: List[EncryptResult], keys: KeyPair) -> List[VerifyResult]:
    """运行 C 语言验证测试"""
    results = []
    script_path = "testcase/c_verify_decrypt_test.py"
    
    if not os.path.exists(script_path):
        print(f"  [!] C 语言验证测试脚本不存在：{script_path}")
        for enc_result in encrypt_results:
            if enc_result.language == "c":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="c",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本不存在：{script_path}",
                suggestion="请检查 c_verify_decrypt_test.py 脚本"
            ))
        return results
    
    print(f"  运行 C 语言验证测试脚本...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] C 语言验证测试脚本执行失败：{stderr[:200]}")
        for enc_result in encrypt_results:
            if enc_result.language == "c":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="c",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本执行失败：{stderr[:100]}",
                suggestion="检查 C DLL 和 MSVC 环境配置"
            ))
        return results
    
    # 读取验证结果
    output_dir = "testcase/results/c_verify"
    summary_file = Path(output_dir) / "summary.json"
    
    if summary_file.exists():
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_data = json.load(f)
        
        for lang_name, lang_data in summary_data.get("languages", {}).items():
            if lang_name == "c":
                continue
            
            for result_entry in lang_data.get("results", []):
                test_id = result_entry.get("test_case_id", 0)
                test_name = result_entry.get("test_case_name", "unknown")
                status = result_entry.get("status", "failed")
                
                expected_plaintext = ""
                for enc_res in encrypt_results:
                    if enc_res.test_case_id == test_id and enc_res.language == lang_name:
                        expected_plaintext = enc_res.plaintext
                        break
                
                if status == "success":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="c",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=True,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=True,
                        signature_valid=True
                    ))
                elif status == "mismatch":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="c",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=False,
                        signature_valid=True,
                        error="解密结果与原始明文不匹配",
                        suggestion=f"期望：{expected_plaintext[:50]}..., 实际：{result_entry.get('decrypted_text', '')[:50]}..."
                    ))
                else:
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="c",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        error=result_entry.get("error", "验签或解密失败"),
                        suggestion="检查密钥格式或 C 实现"
                    ))
    
    return results

def run_cpp_verify_test(encrypt_results: List[EncryptResult], keys: KeyPair) -> List[VerifyResult]:
    """运行 C++ 验证测试"""
    results = []
    script_path = "testcase/cpp_verify_decrypt_test.py"
    
    if not os.path.exists(script_path):
        print(f"  [!] C++ 验证测试脚本不存在：{script_path}")
        for enc_result in encrypt_results:
            if enc_result.language == "cpp":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="cpp",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本不存在：{script_path}",
                suggestion="请检查 cpp_verify_decrypt_test.py 脚本"
            ))
        return results
    
    print(f"  运行 C++ 验证测试脚本...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] C++ 验证测试脚本执行失败：{stderr[:200]}")
        for enc_result in encrypt_results:
            if enc_result.language == "cpp":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="cpp",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本执行失败：{stderr[:100]}",
                suggestion="检查 C++ 环境和库配置"
            ))
        return results
    
    # 读取验证结果
    output_dir = "testcase/results/cpp_verify"
    summary_file = Path(output_dir) / "summary.json"
    
    if summary_file.exists():
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_data = json.load(f)
        
        for lang_name, lang_data in summary_data.get("languages", {}).items():
            if lang_name == "cpp":
                continue
            
            for result_entry in lang_data.get("results", []):
                test_id = result_entry.get("test_case_id", 0)
                test_name = result_entry.get("test_case_name", "unknown")
                status = result_entry.get("status", "failed")
                
                expected_plaintext = ""
                for enc_res in encrypt_results:
                    if enc_res.test_case_id == test_id and enc_res.language == lang_name:
                        expected_plaintext = enc_res.plaintext
                        break
                
                if status == "success":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="cpp",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=True,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=True,
                        signature_valid=True
                    ))
                elif status == "mismatch":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="cpp",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=False,
                        signature_valid=True,
                        error="解密结果与原始明文不匹配",
                        suggestion=f"期望：{expected_plaintext[:50]}..., 实际：{result_entry.get('decrypted_text', '')[:50]}..."
                    ))
                else:
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="cpp",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        error=result_entry.get("error", "验签或解密失败"),
                        suggestion="检查密钥格式或 C++ 实现"
                    ))
    
    return results

def run_csharp_verify_test(encrypt_results: List[EncryptResult], keys: KeyPair) -> List[VerifyResult]:
    """运行 C# 验证测试"""
    results = []
    script_path = "testcase/csharp_verify_decrypt_test.py"
    
    if not os.path.exists(script_path):
        print(f"  [!] C# 验证测试脚本不存在：{script_path}")
        for enc_result in encrypt_results:
            if enc_result.language == "csharp":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="csharp",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本不存在：{script_path}",
                suggestion="请检查 csharp_verify_decrypt_test.py 脚本"
            ))
        return results
    
    print(f"  运行 C# 验证测试脚本...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] C# 验证测试脚本执行失败：{stderr[:200]}")
        for enc_result in encrypt_results:
            if enc_result.language == "csharp":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="csharp",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本执行失败：{stderr[:100]}",
                suggestion="检查 C# 环境和 DLL 配置"
            ))
        return results
    
    # 读取验证结果
    output_dir = "testcase/results/csharp_verify"
    summary_file = Path(output_dir) / "summary.json"
    
    if summary_file.exists():
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_data = json.load(f)
        
        for lang_name, lang_data in summary_data.get("languages", {}).items():
            if lang_name == "csharp":
                continue
            
            for result_entry in lang_data.get("results", []):
                test_id = result_entry.get("test_case_id", 0)
                test_name = result_entry.get("test_case_name", "unknown")
                status = result_entry.get("status", "failed")
                
                expected_plaintext = ""
                for enc_res in encrypt_results:
                    if enc_res.test_case_id == test_id and enc_res.language == lang_name:
                        expected_plaintext = enc_res.plaintext
                        break
                
                if status == "success":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="csharp",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=True,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=True,
                        signature_valid=True
                    ))
                elif status == "mismatch":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="csharp",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=False,
                        signature_valid=True,
                        error="解密结果与原始明文不匹配",
                        suggestion=f"期望：{expected_plaintext[:50]}..., 实际：{result_entry.get('decrypted_text', '')[:50]}..."
                    ))
                else:
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="csharp",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        error=result_entry.get("error", "验签或解密失败"),
                        suggestion="检查密钥格式或 C# 实现"
                    ))
    
    return results

def run_golang_verify_test(encrypt_results: List[EncryptResult], keys: KeyPair) -> List[VerifyResult]:
    """运行 Go 验证测试"""
    results = []
    script_path = "testcase/golang_verify_decrypt_test.py"
    
    if not os.path.exists(script_path):
        print(f"  [!] Go 验证测试脚本不存在：{script_path}")
        for enc_result in encrypt_results:
            if enc_result.language == "golang":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="golang",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本不存在：{script_path}",
                suggestion="请检查 golang_verify_decrypt_test.py 脚本"
            ))
        return results
    
    print(f"  运行 Go 验证测试脚本...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] Go 验证测试脚本执行失败：{stderr[:200]}")
        for enc_result in encrypt_results:
            if enc_result.language == "golang":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="golang",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本执行失败：{stderr[:100]}",
                suggestion="检查 Go 环境和依赖配置"
            ))
        return results
    
    # 读取验证结果
    output_dir = "testcase/results/golang_verify"
    summary_file = Path(output_dir) / "summary.json"
    
    if summary_file.exists():
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_data = json.load(f)
        
        for lang_name, lang_data in summary_data.get("languages", {}).items():
            if lang_name == "golang":
                continue
            
            for result_entry in lang_data.get("results", []):
                test_id = result_entry.get("test_case_id", 0)
                test_name = result_entry.get("test_case_name", "unknown")
                status = result_entry.get("status", "failed")
                
                expected_plaintext = ""
                for enc_res in encrypt_results:
                    if enc_res.test_case_id == test_id and enc_res.language == lang_name:
                        expected_plaintext = enc_res.plaintext
                        break
                
                if status == "success":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="golang",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=True,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=True,
                        signature_valid=True
                    ))
                elif status == "mismatch":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="golang",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=False,
                        signature_valid=True,
                        error="解密结果与原始明文不匹配",
                        suggestion=f"期望：{expected_plaintext[:50]}..., 实际：{result_entry.get('decrypted_text', '')[:50]}..."
                    ))
                else:
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="golang",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        error=result_entry.get("error", "验签或解密失败"),
                        suggestion="检查密钥格式或 Go 实现"
                    ))
    
    return results

def run_javascript_verify_test(encrypt_results: List[EncryptResult], keys: KeyPair) -> List[VerifyResult]:
    """运行 JavaScript 验证测试"""
    results = []
    script_path = "testcase/javascript_verify_decrypt_test.py"
    
    if not os.path.exists(script_path):
        print(f"  [!] JavaScript 验证测试脚本不存在：{script_path}")
        for enc_result in encrypt_results:
            if enc_result.language == "javascript":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="javascript",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本不存在：{script_path}",
                suggestion="请检查 javascript_verify_decrypt_test.py 脚本"
            ))
        return results
    
    print(f"  运行 JavaScript 验证测试脚本...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] JavaScript 验证测试脚本执行失败：{stderr[:200]}")
        for enc_result in encrypt_results:
            if enc_result.language == "javascript":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="javascript",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本执行失败：{stderr[:100]}",
                suggestion="检查 Node.js 环境和依赖配置"
            ))
        return results
    
    # 读取验证结果
    output_dir = "testcase/results/javascript_verify"
    summary_file = Path(output_dir) / "summary.json"
    
    if summary_file.exists():
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_data = json.load(f)
        
        for lang_name, lang_data in summary_data.get("languages", {}).items():
            if lang_name == "javascript":
                continue
            
            for result_entry in lang_data.get("results", []):
                test_id = result_entry.get("test_case_id", 0)
                test_name = result_entry.get("test_case_name", "unknown")
                status = result_entry.get("status", "failed")
                
                expected_plaintext = ""
                for enc_res in encrypt_results:
                    if enc_res.test_case_id == test_id and enc_res.language == lang_name:
                        expected_plaintext = enc_res.plaintext
                        break
                
                if status == "success":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="javascript",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=True,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=True,
                        signature_valid=True
                    ))
                elif status == "mismatch":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="javascript",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=False,
                        signature_valid=True,
                        error="解密结果与原始明文不匹配",
                        suggestion=f"期望：{expected_plaintext[:50]}..., 实际：{result_entry.get('decrypted_text', '')[:50]}..."
                    ))
                else:
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="javascript",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        error=result_entry.get("error", "验签或解密失败"),
                        suggestion="检查密钥格式或 JavaScript 实现"
                    ))
    
    return results

def run_python_verify_test(encrypt_results: List[EncryptResult], keys: KeyPair) -> List[VerifyResult]:
    """运行 Python 验证测试"""
    results = []
    script_path = "testcase/python_verify_decrypt_test.py"
    
    if not os.path.exists(script_path):
        print(f"  [!] Python 验证测试脚本不存在：{script_path}")
        for enc_result in encrypt_results:
            if enc_result.language == "python":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="python",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本不存在：{script_path}",
                suggestion="请检查 python_verify_decrypt_test.py 脚本"
            ))
        return results
    
    print(f"  运行 Python 验证测试脚本...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] Python 验证测试脚本执行失败：{stderr[:200]}")
        for enc_result in encrypt_results:
            if enc_result.language == "python":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="python",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本执行失败：{stderr[:100]}",
                suggestion="检查 Python 环境和依赖配置"
            ))
        return results
    
    # 读取验证结果
    output_dir = "testcase/results/python_verify"
    summary_file = Path(output_dir) / "summary.json"
    
    if summary_file.exists():
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_data = json.load(f)
        
        for lang_name, lang_data in summary_data.get("languages", {}).items():
            if lang_name == "python":
                continue
            
            for result_entry in lang_data.get("results", []):
                test_id = result_entry.get("test_case_id", 0)
                test_name = result_entry.get("test_case_name", "unknown")
                status = result_entry.get("status", "failed")
                
                expected_plaintext = ""
                for enc_res in encrypt_results:
                    if enc_res.test_case_id == test_id and enc_res.language == lang_name:
                        expected_plaintext = enc_res.plaintext
                        break
                
                if status == "success":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="python",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=True,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=True,
                        signature_valid=True
                    ))
                elif status == "mismatch":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="python",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=False,
                        signature_valid=True,
                        error="解密结果与原始明文不匹配",
                        suggestion=f"期望：{expected_plaintext[:50]}..., 实际：{result_entry.get('decrypted_text', '')[:50]}..."
                    ))
                else:
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="python",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        error=result_entry.get("error", "验签或解密失败"),
                        suggestion="检查密钥格式或 Python 实现"
                    ))
    
    return results

def run_rust_verify_test(encrypt_results: List[EncryptResult], keys: KeyPair) -> List[VerifyResult]:
    """运行 Rust 验证测试"""
    results = []
    script_path = "testcase/rust_verify_decrypt_test.py"
    
    if not os.path.exists(script_path):
        print(f"  [!] Rust 验证测试脚本不存在：{script_path}")
        for enc_result in encrypt_results:
            if enc_result.language == "rust":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="rust",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本不存在：{script_path}",
                suggestion="请检查 rust_verify_decrypt_test.py 脚本"
            ))
        return results
    
    print(f"  运行 Rust 验证测试脚本...")
    returncode, stdout, stderr = run_python_script(script_path)
    
    if returncode != 0:
        print(f"  [!] Rust 验证测试脚本执行失败：{stderr[:200]}")
        for enc_result in encrypt_results:
            if enc_result.language == "rust":
                continue
            results.append(VerifyResult(
                encrypt_language=enc_result.language,
                verify_language="rust",
                test_case_id=enc_result.test_case_id,
                test_case_name=enc_result.test_case_name,
                success=False,
                error=f"验证脚本执行失败：{stderr[:100]}",
                suggestion="检查 Rust 环境和 Cargo 配置"
            ))
        return results
    
    # 读取验证结果
    output_dir = "testcase/results/rust_verify"
    summary_file = Path(output_dir) / "summary.json"
    
    if summary_file.exists():
        with open(summary_file, 'r', encoding='utf-8') as f:
            summary_data = json.load(f)
        
        for lang_name, lang_data in summary_data.get("languages", {}).items():
            if lang_name == "rust":
                continue
            
            for result_entry in lang_data.get("results", []):
                test_id = result_entry.get("test_case_id", 0)
                test_name = result_entry.get("test_case_name", "unknown")
                status = result_entry.get("status", "failed")
                
                expected_plaintext = ""
                for enc_res in encrypt_results:
                    if enc_res.test_case_id == test_id and enc_res.language == lang_name:
                        expected_plaintext = enc_res.plaintext
                        break
                
                if status == "success":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="rust",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=True,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=True,
                        signature_valid=True
                    ))
                elif status == "mismatch":
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="rust",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        decrypted_text=result_entry.get("decrypted_text", ""),
                        plaintext_matched=False,
                        signature_valid=True,
                        error="解密结果与原始明文不匹配",
                        suggestion=f"期望：{expected_plaintext[:50]}..., 实际：{result_entry.get('decrypted_text', '')[:50]}..."
                    ))
                else:
                    results.append(VerifyResult(
                        encrypt_language=lang_name,
                        verify_language="rust",
                        test_case_id=test_id,
                        test_case_name=test_name,
                        success=False,
                        error=result_entry.get("error", "验签或解密失败"),
                        suggestion="检查密钥格式或 Rust 实现"
                    ))
    
    return results

# ============================================================================
# 报告生成函数
# ============================================================================

def generate_report(report: TestReport) -> None:
    """生成测试报告"""
    # 保存 JSON 报告
    report_dict = {
        "start_time": report.start_time,
        "end_time": report.end_time,
        "total_duration_seconds": report.total_duration_seconds,
        "languages_tested": report.languages_tested,
        "encrypt_results": [
            {
                "test_case_id": r.test_case_id,
                "test_case_name": r.test_case_name,
                "plaintext": r.plaintext,
                "ciphertext_hex": r.ciphertext_hex,
                "signature_hex": r.signature_hex,
                "language": r.language,
                "success": r.success,
                "error": r.error,
                "duration_ms": r.duration_ms
            }
            for r in report.encrypt_results
        ],
        "verify_results": [
            {
                "encrypt_language": r.encrypt_language,
                "verify_language": r.verify_language,
                "test_case_id": r.test_case_id,
                "test_case_name": r.test_case_name,
                "success": r.success,
                "decrypted_text": r.decrypted_text,
                "plaintext_matched": r.plaintext_matched,
                "signature_valid": r.signature_valid,
                "error": r.error,
                "suggestion": r.suggestion,
                "duration_ms": r.duration_ms
            }
            for r in report.verify_results
        ],
        "summary": report.summary,
        "errors": report.errors,
        "suggestions": report.suggestions
    }
    
    save_json_file(REPORT_FILE, report_dict)
    print(f"\n[OK] JSON 报告已保存：{REPORT_FILE}")
    
    # 生成 Markdown 报告
    generate_markdown_report(report)

def generate_markdown_report(report: TestReport) -> None:
    """生成 Markdown 格式的报告"""
    md_lines = [
        "# 跨语言 SM2 互通性测试报告",
        "",
        f"**测试时间**: {report.start_time} - {report.end_time or '进行中'}",
        f"**总耗时**: {format_duration(report.total_duration_seconds)}",
        "",
        "## 测试摘要",
        "",
    ]
    
    # 加密测试摘要
    encrypt_success = sum(1 for r in report.encrypt_results if r.success)
    encrypt_total = len(report.encrypt_results)
    md_lines.append(f"### 加密测试")
    md_lines.append(f"- 总计：{encrypt_total}")
    md_lines.append(f"- 成功：{encrypt_success}")
    md_lines.append(f"- 失败：{encrypt_total - encrypt_success}")
    md_lines.append("")
    
    # 验证测试摘要
    verify_success = sum(1 for r in report.verify_results if r.success)
    verify_total = len(report.verify_results)
    md_lines.append(f"### 验证测试")
    md_lines.append(f"- 总计：{verify_total}")
    md_lines.append(f"- 成功：{verify_success}")
    md_lines.append(f"- 失败：{verify_total - verify_success}")
    if verify_total > 0:
        rate = verify_success / verify_total * 100
        md_lines.append(f"- 成功率：{rate:.1f}%")
    md_lines.append("")
    
    # 详细结果
    md_lines.append("## 加密测试详细结果")
    md_lines.append("")
    md_lines.append("| 语言 | 测试用例 | 状态 | 耗时 |")
    md_lines.append("|------|----------|------|------|")
    
    for r in report.encrypt_results:
        status = "OK" if r.success else "FAIL"
        md_lines.append(f"| {r.language} | {r.test_case_name} | {status} | {r.duration_ms}ms |")
    
    md_lines.append("")
    md_lines.append("## 验证测试详细结果")
    md_lines.append("")
    md_lines.append("| 加密语言 | 验证语言 | 测试用例 | 状态 | 错误信息 |")
    md_lines.append("|----------|----------|----------|------|----------|")
    
    for r in report.verify_results:
        status = "OK" if r.success else "FAIL"
        error = r.error[:30] + "..." if r.error and len(r.error) > 30 else (r.error or "")
        md_lines.append(f"| {r.encrypt_language} | {r.verify_language} | {r.test_case_name} | {status} | {error} |")
    
    md_lines.append("")
    
    # 错误和建议
    if report.errors:
        md_lines.append("## 错误列表")
        md_lines.append("")
        for i, error in enumerate(report.errors, 1):
            md_lines.append(f"{i}. **{error['language']}**: {error['message']}")
        md_lines.append("")
    
    if report.suggestions:
        md_lines.append("## 改进建议")
        md_lines.append("")
        for i, suggestion in enumerate(report.suggestions, 1):
            md_lines.append(f"{i}. {suggestion}")
        md_lines.append("")
    
    # 保存 Markdown 报告
    with open(REPORT_MD_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md_lines))
    
    print(f"[OK] Markdown 报告已保存：{REPORT_MD_FILE}")

# ============================================================================
# 主测试流程
# ============================================================================

def run_all_tests(encrypt_only: bool = False, verify_only: bool = False, 
                  target_language: Optional[Language] = None) -> TestReport:
    """运行所有测试"""
    
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = TestReport(start_time=start_time)
    
    print("=" * 80)
    print("跨语言 SM2 互通性测试")
    print("=" * 80)
    print(f"开始时间：{start_time}")
    print(f"模式：{'仅加密' if encrypt_only else '仅验证' if verify_only else '完整测试'}")
    if target_language:
        print(f"目标语言：{target_language}")
    print("=" * 80)
    
    # 加载测试数据
    print("\n[1] 加载测试数据...")
    test_cases = load_test_data()
    print(f"    加载 {len(test_cases)} 个测试用例")
    
    # 运行加密测试
    if not verify_only:
        print("\n[2] 运行加密测试...")
        print("-" * 80)
        
        encrypt_functions = {
            Language.JAVA: run_java_encrypt_test,
            Language.C: run_c_encrypt_test,
            Language.CPP: run_cpp_encrypt_test,
            Language.CSHARP: run_csharp_encrypt_test,
            Language.GOLANG: run_golang_encrypt_test,
            Language.JAVASCRIPT: run_javascript_encrypt_test,
            Language.PYTHON: run_python_encrypt_test,
            Language.RUST: run_rust_encrypt_test,
        }
        
        languages_to_test = [target_language] if target_language else ALL_LANGUAGES
        
        for lang in languages_to_test:
            print(f"\n  [{lang}] 加载密钥...")
            try:
                keys = load_keys(lang)
                print(f"    加密公钥：{keys.encryption_public_key_hex[:40]}...")
                print(f"    签名私钥：{keys.signature_private_key_hex[:40]}...")
                
                print(f"  [{lang}] 执行加密测试...")
                results = encrypt_functions[lang](test_cases, keys)
                report.encrypt_results.extend(results)
                report.languages_tested.append(str(lang))
                
                success_count = sum(1 for r in results if r.success)
                print(f"    结果：{success_count}/{len(results)} 成功")
                
            except Exception as e:
                error_msg = f"{lang} 加密测试失败：{str(e)}"
                print(f"    [!] {error_msg}")
                report.errors.append({
                    "language": str(lang),
                    "phase": "encrypt",
                    "message": str(e)
                })
                report.suggestions.append(f"检查 {lang} 环境的编译和配置")
        
        print("\n" + "-" * 80)
        total_encrypt = len(report.encrypt_results)
        success_encrypt = sum(1 for r in report.encrypt_results if r.success)
        print(f"加密测试完成：{success_encrypt}/{total_encrypt} 成功")
    
    # 运行验证测试
    if not encrypt_only and report.encrypt_results:
        print("\n[3] 运行验证测试...")
        print("-" * 80)
        
        verify_functions = {
            Language.JAVA: run_java_verify_test,
            Language.C: run_c_verify_test,
            Language.CPP: run_cpp_verify_test,
            Language.CSHARP: run_csharp_verify_test,
            Language.GOLANG: run_golang_verify_test,
            Language.JAVASCRIPT: run_javascript_verify_test,
            Language.PYTHON: run_python_verify_test,
            Language.RUST: run_rust_verify_test,
        }
        
        languages_to_verify = [target_language] if target_language else ALL_LANGUAGES
        
        for lang in languages_to_verify:
            print(f"\n  [{lang}] 执行验证测试...")
            try:
                keys = load_keys(lang)
                results = verify_functions[lang](report.encrypt_results, keys)
                report.verify_results.extend(results)
                
                success_count = sum(1 for r in results if r.success)
                print(f"    结果：{success_count}/{len(results)} 成功")
                
            except Exception as e:
                error_msg = f"{lang} 验证测试失败：{str(e)}"
                print(f"    [!] {error_msg}")
                report.errors.append({
                    "language": str(lang),
                    "phase": "verify",
                    "message": str(e)
                })
        
        print("\n" + "-" * 80)
        total_verify = len(report.verify_results)
        success_verify = sum(1 for r in report.verify_results if r.success)
        print(f"验证测试完成：{success_verify}/{total_verify} 成功")
    
    # 生成摘要
    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report.end_time = end_time
    report.total_duration_seconds = (datetime.now() - datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")).total_seconds()
    
    report.summary = {
        "total_encrypt_tests": len(report.encrypt_results),
        "success_encrypt_tests": sum(1 for r in report.encrypt_results if r.success),
        "failed_encrypt_tests": sum(1 for r in report.encrypt_results if not r.success),
        "total_verify_tests": len(report.verify_results),
        "success_verify_tests": sum(1 for r in report.verify_results if r.success),
        "failed_verify_tests": sum(1 for r in report.verify_results if not r.success),
        "total_errors": len(report.errors),
        "total_suggestions": len(report.suggestions)
    }
    
    # 生成报告
    print("\n[4] 生成测试报告...")
    generate_report(report)
    
    # 打印总结
    print("\n" + "=" * 80)
    print("测试总结")
    print("=" * 80)
    print(f"测试时间：{start_time} - {end_time}")
    print(f"总耗时：{format_duration(report.total_duration_seconds)}")
    print(f"加密测试：{report.summary['success_encrypt_tests']}/{report.summary['total_encrypt_tests']} 成功")
    print(f"验证测试：{report.summary['success_verify_tests']}/{report.summary['total_verify_tests']} 成功")
    print(f"错误数量：{report.summary['total_errors']}")
    print(f"建议数量：{report.summary['total_suggestions']}")
    print("=" * 80)
    
    return report

# ============================================================================
# 主入口
# ============================================================================

def main():
    """主入口"""
    parser = argparse.ArgumentParser(
        description="跨语言 SM2 互通性测试主框架",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python run_all_interop_tests.py                    # 运行完整测试
  python run_all_interop_tests.py --encrypt-only     # 仅运行加密测试
  python run_all_interop_tests.py --verify-only      # 仅运行验证测试
  python run_all_interop_tests.py --language java    # 仅测试 Java
        """
    )
    
    parser.add_argument(
        "--encrypt-only",
        action="store_true",
        help="仅执行加密测试"
    )
    
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="仅执行验证测试"
    )
    
    parser.add_argument(
        "--language",
        type=str,
        choices=[lang.value for lang in ALL_LANGUAGES],
        help="指定要测试的语言"
    )
    
    args = parser.parse_args()
    
    # 解析目标语言
    target_language = Language(args.language) if args.language else None
    
    # 运行测试
    try:
        report = run_all_tests(
            encrypt_only=args.encrypt_only,
            verify_only=args.verify_only,
            target_language=target_language
        )
        
        # 返回退出码
        has_failures = (
            report.summary['failed_encrypt_tests'] > 0 or
            report.summary['failed_verify_tests'] > 0
        )
        sys.exit(1 if has_failures else 0)
        
    except KeyboardInterrupt:
        print("\n\n测试被用户中断")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] 测试过程中发生异常：{e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()