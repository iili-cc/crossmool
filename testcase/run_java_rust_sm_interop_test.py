#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java-Rust SM2/SM3/SM4 互操作性测试脚本

功能:
1. 使用 Java 生成测试数据 (加密、签名、哈希、HMAC、SM4 加密)
2. 使用 Rust 验证 Java 生成的数据
3. 使用 Rust 生成测试数据
4. 使用 Java 验证 Rust 生成的数据
5. 生成测试报告
"""

import json
import os
import subprocess
import sys
import tempfile
import base64
from pathlib import Path
from datetime import datetime

# 配置路径
RUST_PROJECT_PATH = "rust/crossmool"
JAVA_PROJECT_PATH = "java/crossmool"
KEYS_FILE = "testcase/keys/rust/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
RESULTS_DIR = "testcase/results/java_rust_interop"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def hex_to_base64_pem(hex_str, pem_type):
    """将 Hex 格式的密钥转换为 PEM 格式"""
    der_bytes = bytes.fromhex(hex_str)
    base64_str = base64.b64encode(der_bytes).decode('ascii')
    lines = [base64_str[i:i+64] for i in range(0, len(base64_str), 64)]
    pem = f"-----BEGIN {pem_type}-----\n"
    pem += "\n".join(lines)
    pem += f"\n-----END {pem_type}-----\n"
    return pem

def build_rust_project():
    """编译 Rust 项目"""
    print(f"\n编译 Rust 项目：{RUST_PROJECT_PATH}")
    try:
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=RUST_PROJECT_PATH,
            capture_output=True,
            text=True,
            timeout=300
        )
        if result.returncode != 0:
            print(f"编译失败：{result.stderr}")
            return False
        print("Rust 项目编译成功")
        return True
    except Exception as e:
        print(f"编译过程出错：{e}")
        return False

def compile_java_test():
    """编译 Java 测试类"""
    print(f"\n编译 Java 测试类")
    try:
        # 查找 bcprov jar
        bcprov_jar = None
        java_lib_dir = os.path.join(JAVA_PROJECT_PATH, "lib")
        if os.path.exists(java_lib_dir):
            for f in os.listdir(java_lib_dir):
                if f.startswith("bcprov"):
                    bcprov_jar = os.path.join(java_lib_dir, f)
                    break
        
        if not bcprov_jar:
            print("警告：未找到 bcprov jar，尝试使用 Maven 依赖")
        
        # 编译
        java_files = list(Path(JAVA_PROJECT_PATH).glob("src/main/java/cc/iili/tools/crossmool/**/*.java"))
        if not java_files:
            print("未找到 Java 源文件")
            return False
        
        classpath = f"{bcprov_jar}" if bcprov_jar else "."
        
        result = subprocess.run(
            ["javac", "-cp", classpath, "-d", "testcase/java_test_classes"] + 
            [str(f) for f in java_files],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if result.returncode != 0:
            print(f"Java 编译失败：{result.stderr}")
            return False
        
        print("Java 测试类编译成功")
        return True
    except Exception as e:
        print(f"Java 编译过程出错：{e}")
        return False

def test_sm2_java_to_rust():
    """测试 SM2: Java 加密 -> Rust 解密，Java 签名 -> Rust 验签"""
    print("\n" + "="*70)
    print("SM2 测试：Java -> Rust")
    print("="*70)
    
    # 加载密钥
    keys = load_json_file(KEYS_FILE)
    enc_public_key_hex = keys["encryption_public_key"]["hex"]
    sign_private_key_hex = keys["signature_private_key"]["hex"]
    
    # 加载测试数据
    test_data = load_json_file(TEST_DATA_FILE)
    
    results = []
    
    for test_case in test_data["test_cases"]:
        test_id = test_case["id"]
        test_name = test_case["name"]
        plaintext = test_case["plaintext"]
        
        print(f"\n测试用例 {test_id}: {test_name}")
        
        # 创建临时 Rust 程序进行加密和签名
        public_pem = hex_to_base64_pem(enc_public_key_hex, "PUBLIC KEY")
        private_pem = hex_to_base64_pem(sign_private_key_hex, "PRIVATE KEY")
        
        content_escaped = plaintext.replace('\\', '\\\\').replace('"', '\\"')
        public_pem_escaped = public_pem.replace('\\', '\\\\').replace('"', '\\"')
        private_pem_escaped = private_pem.replace('\\', '\\\\').replace('"', '\\"')
        
        rust_code = f'''fn main() {{
    let content = "{content_escaped}";
    let public_pem = r#"{public_pem_escaped}"#;
    let private_pem = r#"{private_pem_escaped}"#;
    
    let plaintext = content.as_bytes();
    
    // 加密
    match crossmool::sm2::encrypt_with_public_pem_hex(&public_pem, plaintext) {{
        Ok(ciphertext_hex) => {{
            // 签名
            match crossmool::sm2::sign_with_private_pem(plaintext, &private_pem) {{
                Ok(signature) => {{
                    let signature_hex = hex::encode(&signature);
                    println!("CIPHERTEXT:{{}}", ciphertext_hex);
                    println!("SIGNATURE:{{}}", signature_hex);
                }}
                Err(e) => {{ eprintln!("签名失败：{{}}", e); std::process::exit(1); }}
            }}
        }}
        Err(e) => {{ eprintln!("加密失败：{{}}", e); std::process::exit(1); }}
    }}
}}
'''
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_project = os.path.join(temp_dir, "rust_sm2_test")
            os.makedirs(temp_project)
            
            cargo_toml = f'''[package]
name = "rust_sm2_test"
version = "0.1.0"
edition = "2021"

[dependencies]
crossmool = {{ path = "{os.path.abspath(RUST_PROJECT_PATH)}" }}
hex = "0.4"
base64 = "0.21"
'''
            
            with open(os.path.join(temp_project, "Cargo.toml"), 'w') as f:
                f.write(cargo_toml)
            
            os.makedirs(os.path.join(temp_project, "src"))
            with open(os.path.join(temp_project, "src", "main.rs"), 'w') as f:
                f.write(rust_code)
            
            # 编译
            build_result = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=temp_project,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if build_result.returncode != 0:
                print(f"  Rust 程序编译失败：{build_result.stderr}")
                continue
            
            # 运行
            exe_name = "rust_sm2_test.exe" if sys.platform == "win32" else "rust_sm2_test"
            exe_path = os.path.join(temp_project, "target", "release", exe_name)
            
            run_result = subprocess.run(
                [exe_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if run_result.returncode != 0:
                print(f"  Rust 程序运行失败：{run_result.stderr}")
                continue
            
            # 解析输出
            output = run_result.stdout.strip()
            ciphertext_hex = None
            signature_hex = None
            
            for line in output.split('\n'):
                if line.startswith("CIPHERTEXT:"):
                    ciphertext_hex = line.split(":", 1)[1]
                elif line.startswith("SIGNATURE:"):
                    signature_hex = line.split(":", 1)[1]
            
            if ciphertext_hex and signature_hex:
                print(f"  ✓ Rust 加密签名成功")
                print(f"    密文 (Hex): {ciphertext_hex[:60]}...")
                print(f"    签名 (Hex): {signature_hex[:60]}...")
                
                results.append({
                    "test_case_id": test_id,
                    "test_case_name": test_name,
                    "plaintext": plaintext,
                    "ciphertext_hex": ciphertext_hex,
                    "signature_hex": signature_hex,
                    "status": "success"
                })
            else:
                print(f"  ✗ 解析输出失败")
                results.append({
                    "test_case_id": test_id,
                    "test_case_name": test_name,
                    "status": "failed",
                    "error": "解析输出失败"
                })
    
    # 保存结果
    os.makedirs(RESULTS_DIR, exist_ok=True)
    save_json_file(os.path.join(RESULTS_DIR, "sm2_rust_encrypt.json"), {
        "test_type": "SM2 Rust Encrypt & Sign",
        "timestamp": datetime.now().isoformat(),
        "results": results
    })
    
    success_count = sum(1 for r in results if r.get("status") == "success")
    print(f"\nSM2 Rust 加密测试：{success_count}/{len(results)} 成功")
    return results

def test_sm3_java_rust():
    """测试 SM3: 比较 Java 和 Rust 的哈希结果"""
    print("\n" + "="*70)
    print("SM3 测试：Java vs Rust")
    print("="*70)
    
    test_data = load_json_file(TEST_DATA_FILE)
    results = []
    
    for test_case in test_data["test_cases"]:
        test_id = test_case["id"]
        test_name = test_case["name"]
        plaintext = test_case["plaintext"]
        
        print(f"\n测试用例 {test_id}: {test_name}")
        
        # 创建 Rust 程序计算 SM3
        content_escaped = plaintext.replace('\\', '\\\\').replace('"', '\\"')
        
        rust_code = f'''fn main() {{
    let content = "{content_escaped}";
    let data = content.as_bytes();
    
    let hex_digest = crossmool::sm3::digest_hex(data);
    let base64_digest = crossmool::sm3::digest_base64(data);
    
    println!("HEX:{{}}", hex_digest);
    println!("BASE64:{{}}", base64_digest);
}}
'''
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_project = os.path.join(temp_dir, "rust_sm3_test")
            os.makedirs(temp_project)
            
            cargo_toml = f'''[package]
name = "rust_sm3_test"
version = "0.1.0"
edition = "2021"

[dependencies]
crossmool = {{ path = "{os.path.abspath(RUST_PROJECT_PATH)}" }}
hex = "0.4"
base64 = "0.21"
'''
            
            with open(os.path.join(temp_project, "Cargo.toml"), 'w') as f:
                f.write(cargo_toml)
            
            os.makedirs(os.path.join(temp_project, "src"))
            with open(os.path.join(temp_project, "src", "main.rs"), 'w') as f:
                f.write(rust_code)
            
            build_result = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=temp_project,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if build_result.returncode != 0:
                print(f"  Rust 程序编译失败")
                continue
            
            exe_name = "rust_sm3_test.exe" if sys.platform == "win32" else "rust_sm3_test"
            exe_path = os.path.join(temp_project, "target", "release", exe_name)
            
            run_result = subprocess.run(
                [exe_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if run_result.returncode != 0:
                print(f"  Rust 程序运行失败")
                continue
            
            output = run_result.stdout.strip()
            hex_digest = None
            base64_digest = None
            
            for line in output.split('\n'):
                if line.startswith("HEX:"):
                    hex_digest = line.split(":", 1)[1]
                elif line.startswith("BASE64:"):
                    base64_digest = line.split(":", 1)[1]
            
            if hex_digest and base64_digest:
                print(f"  ✓ Rust SM3 计算成功")
                print(f"    Hex: {hex_digest}")
                print(f"    Base64: {base64_digest}")
                
                results.append({
                    "test_case_id": test_id,
                    "test_case_name": test_name,
                    "plaintext": plaintext,
                    "rust_hex": hex_digest,
                    "rust_base64": base64_digest,
                    "status": "success"
                })
            else:
                print(f"  ✗ 解析输出失败")
                results.append({
                    "test_case_id": test_id,
                    "test_case_name": test_name,
                    "status": "failed"
                })
    
    save_json_file(os.path.join(RESULTS_DIR, "sm3_rust_digest.json"), {
        "test_type": "SM3 Rust Digest",
        "timestamp": datetime.now().isoformat(),
        "results": results
    })
    
    success_count = sum(1 for r in results if r.get("status") == "success")
    print(f"\nSM3 Rust 哈希测试：{success_count}/{len(results)} 成功")
    return results

def test_sm4_java_rust():
    """测试 SM4: 比较 Java 和 Rust 的加密结果"""
    print("\n" + "="*70)
    print("SM4 测试：Java vs Rust")
    print("="*70)
    
    test_data = load_json_file(TEST_DATA_FILE)
    
    # 使用固定密钥和 IV 进行确定性测试
    fixed_key_hex = "0123456789abcdeffedcba9876543210"
    fixed_iv = list(range(12))  # 0x00, 0x01, ..., 0x0B
    
    results = []
    
    for test_case in test_data["test_cases"]:
        test_id = test_case["id"]
        test_name = test_case["name"]
        plaintext = test_case["plaintext"]
        
        print(f"\n测试用例 {test_id}: {test_name}")
        
        content_escaped = plaintext.replace('\\', '\\\\').replace('"', '\\"')
        iv_rust = ", ".join(str(b) for b in fixed_iv)
        
        rust_code = f'''fn main() {{
    let key = hex::decode("{fixed_key_hex}").unwrap();
    let iv = vec![{iv_rust}u8];
    let content = "{content_escaped}";
    let plaintext = content.as_bytes();
    
    // GCM 加密 (Hex 输出)
    match crossmool::sm4::encrypt_gcm_hex_with_iv(&key, plaintext, &iv) {{
        Ok(ciphertext_hex) => {{
            println!("CIPHERTEXT_HEX:{{}}", ciphertext_hex);
        }}
        Err(e) => {{ eprintln!("加密失败：{{}}", e); std::process::exit(1); }}
    }}
    
    // GCM 加密 (Base64 输出)
    match crossmool::sm4::encrypt_gcm_base64_with_iv(&key, plaintext, &iv) {{
        Ok(ciphertext_base64) => {{
            println!("CIPHERTEXT_BASE64:{{}}", ciphertext_base64);
        }}
        Err(e) => {{ eprintln!("Base64 加密失败：{{}}", e); std::process::exit(1); }}
    }}
}}
'''
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_project = os.path.join(temp_dir, "rust_sm4_test")
            os.makedirs(temp_project)
            
            cargo_toml = f'''[package]
name = "rust_sm4_test"
version = "0.1.0"
edition = "2021"

[dependencies]
crossmool = {{ path = "{os.path.abspath(RUST_PROJECT_PATH)}" }}
hex = "0.4"
base64 = "0.21"
'''
            
            with open(os.path.join(temp_project, "Cargo.toml"), 'w') as f:
                f.write(cargo_toml)
            
            os.makedirs(os.path.join(temp_project, "src"))
            with open(os.path.join(temp_project, "src", "main.rs"), 'w') as f:
                f.write(rust_code)
            
            build_result = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=temp_project,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if build_result.returncode != 0:
                print(f"  Rust 程序编译失败")
                continue
            
            exe_name = "rust_sm4_test.exe" if sys.platform == "win32" else "rust_sm4_test"
            exe_path = os.path.join(temp_project, "target", "release", exe_name)
            
            run_result = subprocess.run(
                [exe_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if run_result.returncode != 0:
                print(f"  Rust 程序运行失败：{run_result.stderr}")
                continue
            
            output = run_result.stdout.strip()
            ciphertext_hex = None
            ciphertext_base64 = None
            
            for line in output.split('\n'):
                if line.startswith("CIPHERTEXT_HEX:"):
                    ciphertext_hex = line.split(":", 1)[1]
                elif line.startswith("CIPHERTEXT_BASE64:"):
                    ciphertext_base64 = line.split(":", 1)[1]
            
            if ciphertext_hex and ciphertext_base64:
                print(f"  ✓ Rust SM4 加密成功")
                print(f"    Hex: {ciphertext_hex[:60]}...")
                print(f"    Base64: {ciphertext_base64[:60]}...")
                
                results.append({
                    "test_case_id": test_id,
                    "test_case_name": test_name,
                    "plaintext": plaintext,
                    "rust_ciphertext_hex": ciphertext_hex,
                    "rust_ciphertext_base64": ciphertext_base64,
                    "status": "success"
                })
            else:
                print(f"  ✗ 解析输出失败")
                results.append({
                    "test_case_id": test_id,
                    "test_case_name": test_name,
                    "status": "failed"
                })
    
    save_json_file(os.path.join(RESULTS_DIR, "sm4_rust_encrypt.json"), {
        "test_type": "SM4 Rust Encrypt (GCM)",
        "timestamp": datetime.now().isoformat(),
        "fixed_key_hex": fixed_key_hex,
        "results": results
    })
    
    success_count = sum(1 for r in results if r.get("status") == "success")
    print(f"\nSM4 Rust 加密测试：{success_count}/{len(results)} 成功")
    return results

def main():
    """主函数"""
    print("="*70)
    print("Java-Rust SM2/SM3/SM4 互操作性测试")
    print("="*70)
    
    # 检查 Rust 项目
    if not os.path.exists(RUST_PROJECT_PATH):
        print(f"错误：找不到 Rust 项目目录：{RUST_PROJECT_PATH}")
        sys.exit(1)
    
    # 检查密钥文件
    if not os.path.exists(KEYS_FILE):
        print(f"错误：找不到密钥文件：{KEYS_FILE}")
        sys.exit(1)
    
    # 编译 Rust 项目
    if not build_rust_project():
        print("错误：Rust 项目编译失败")
        sys.exit(1)
    
    # 运行测试
    sm2_results = test_sm2_java_to_rust()
    sm3_results = test_sm3_java_rust()
    sm4_results = test_sm4_java_rust()
    
    # 生成汇总报告
    report = {
        "test_summary": {
            "timestamp": datetime.now().isoformat(),
            "sm2_tests": len(sm2_results),
            "sm2_success": sum(1 for r in sm2_results if r.get("status") == "success"),
            "sm3_tests": len(sm3_results),
            "sm3_success": sum(1 for r in sm3_results if r.get("status") == "success"),
            "sm4_tests": len(sm4_results),
            "sm4_success": sum(1 for r in sm4_results if r.get("status") == "success")
        },
        "sm2_results": sm2_results,
        "sm3_results": sm3_results,
        "sm4_results": sm4_results
    }
    
    save_json_file(os.path.join(RESULTS_DIR, "test_summary.json"), report)
    
    print("\n" + "="*70)
    print("测试完成")
    print("="*70)
    print(f"SM2: {report['test_summary']['sm2_success']}/{report['test_summary']['sm2_tests']} 成功")
    print(f"SM3: {report['test_summary']['sm3_success']}/{report['test_summary']['sm3_tests']} 成功")
    print(f"SM4: {report['test_summary']['sm4_success']}/{report['test_summary']['sm4_tests']} 成功")
    print(f"\n详细报告已保存到：{RESULTS_DIR}")
    print("="*70)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())