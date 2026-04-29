#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rust 语言 SM2 加密和签名互操作性测试脚本

功能:
1. 读取 testcase/keys/rust/keys.json 中的密钥
2. 读取 testcase/test_data.json 中的测试数据
3. 使用 cargo build --release 编译 rust/crossmool 项目
4. 创建临时 Rust 程序调用 crossmool 库执行加密签名
5. 输出 Hex 格式的密文和签名到 testcase/results/rust_encrypt 目录
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# 配置路径
RUST_PROJECT_PATH = "rust/crossmool"
KEYS_FILE = "testcase/keys/rust/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/rust_encrypt"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def build_rust_project():
    """编译 Rust 项目"""
    print(f"\n编译 Rust 项目：{RUST_PROJECT_PATH}")
    
    # 检查 Cargo.toml 是否存在
    cargo_toml = os.path.join(RUST_PROJECT_PATH, "Cargo.toml")
    if not os.path.exists(cargo_toml):
        print(f"错误：找不到 Cargo.toml 文件：{cargo_toml}")
        return False
    
    # 执行 cargo build --release
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
    except subprocess.TimeoutExpired:
        print("错误：编译超时")
        return False
    except Exception as e:
        print(f"编译过程出错：{e}")
        return False

def hex_to_base64_pem(hex_str, pem_type):
    """将 Hex 格式的密钥转换为 PEM 格式"""
    import base64
    
    # Hex 转 bytes
    der_bytes = bytes.fromhex(hex_str)
    
    # bytes 转 Base64
    base64_str = base64.b64encode(der_bytes).decode('ascii')
    
    # 每 64 字符换行
    lines = [base64_str[i:i+64] for i in range(0, len(base64_str), 64)]
    
    # 构建 PEM
    pem = f"-----BEGIN {pem_type}-----\n"
    pem += "\n".join(lines)
    pem += f"\n-----END {pem_type}-----\n"
    
    return pem

def run_rust_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    """
    创建临时 Rust 程序执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 将 Hex 密钥转换为 PEM 格式
    public_pem = hex_to_base64_pem(enc_public_key_hex, "PUBLIC KEY")
    private_pem = hex_to_base64_pem(sign_private_key_hex, "PRIVATE KEY")
    
    # 转义 Rust 字符串中的特殊字符
    content_escaped = content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    public_pem_escaped = public_pem.replace('\\', '\\\\').replace('"', '\\"')
    private_pem_escaped = private_pem.replace('\\', '\\\\').replace('"', '\\"')
    
    # 创建临时 Rust 程序
    rust_code = f'''use std::process;

fn main() {{
    let content = "{content_escaped}";
    let public_pem = r#"{public_pem_escaped}"#;
    let private_pem = r#"{private_pem_escaped}"#;
    
    // 加密
    let plaintext = content.as_bytes();
    match crossmool::sm2::encrypt_with_public_pem_hex(&public_pem, plaintext) {{
        Ok(ciphertext_hex) => {{
            // 签名
            match crossmool::sm2::sign_with_private_pem(plaintext, &private_pem) {{
                Ok(signature) => {{
                    let signature_hex = hex::encode(&signature);
                    // 输出格式：密文\\t签名
                    println!("{{}}\\t{{}}", ciphertext_hex, signature_hex);
                }}
                Err(e) => {{
                    eprintln!("签名失败：{{}}", e);
                    process::exit(1);
                }}
            }}
        }}
        Err(e) => {{
            eprintln!("加密失败：{{}}", e);
            process::exit(1);
        }}
    }}
}}
'''
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_project = os.path.join(temp_dir, "rust_test_temp")
        os.makedirs(temp_project)
        
        # 创建 Cargo.toml
        cargo_toml_content = '''[package]
name = "rust_test_temp"
version = "0.1.0"
edition = "2021"

[dependencies]
crossmool = { path = "''' + os.path.abspath(RUST_PROJECT_PATH) + '''" }
hex = "0.4"
base64 = "0.21"
'''
        
        cargo_toml_path = os.path.join(temp_project, "Cargo.toml")
        with open(cargo_toml_path, 'w', encoding='utf-8') as f:
            f.write(cargo_toml_content)
        
        # 创建 src 目录
        src_dir = os.path.join(temp_project, "src")
        os.makedirs(src_dir)
        
        # 创建 main.rs
        main_rs_path = os.path.join(src_dir, "main.rs")
        with open(main_rs_path, 'w', encoding='utf-8') as f:
            f.write(rust_code)
        
        try:
            # 编译临时项目
            print("  编译临时 Rust 程序...")
            build_result = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=temp_project,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if build_result.returncode != 0:
                print(f"  临时程序编译失败：{build_result.stderr}")
                return None
            
            # 运行程序
            exe_name = "rust_test_temp"
            if sys.platform == "win32":
                exe_name += ".exe"
            
            exe_path = os.path.join(temp_project, "target", "release", exe_name)
            
            run_result = subprocess.run(
                [exe_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if run_result.returncode != 0:
                print(f"  程序运行失败：{run_result.stderr}")
                return None
            
            # 解析输出
            output = run_result.stdout.strip()
            parts = output.split('\t')
            if len(parts) == 2:
                return {
                    "ciphertext": parts[0],
                    "signature": parts[1]
                }
            else:
                print(f"  输出格式错误：{output}")
                return None
                
        except subprocess.TimeoutExpired:
            print("  错误：编译或运行超时")
            return None
        except Exception as e:
            print(f"  编译或运行过程出错：{e}")
            return None

def main():
    """主函数"""
    print("=" * 60)
    print("Rust 语言 SM2 加密和签名互操作性测试")
    print("=" * 60)
    
    # 检查密钥文件
    if not os.path.exists(KEYS_FILE):
        print(f"错误：找不到密钥文件：{KEYS_FILE}")
        sys.exit(1)
    
    # 检查测试数据文件
    if not os.path.exists(TEST_DATA_FILE):
        print(f"错误：找不到测试数据文件：{TEST_DATA_FILE}")
        sys.exit(1)
    
    # 加载密钥
    print(f"\n加载密钥文件：{KEYS_FILE}")
    keys = load_json_file(KEYS_FILE)
    enc_public_key_hex = keys["encryption_public_key"]["hex"]
    sign_private_key_hex = keys["signature_private_key"]["hex"]
    print(f"  加密公钥 (Hex): {enc_public_key_hex[:40]}...")
    print(f"  签名私钥 (Hex): {sign_private_key_hex[:40]}...")
    
    # 加载测试数据
    print(f"\n加载测试数据：{TEST_DATA_FILE}")
    test_data = load_json_file(TEST_DATA_FILE)
    test_cases = test_data["test_cases"]
    print(f"  测试用例数量：{len(test_cases)}")
    
    # 编译 Rust 项目
    if not build_rust_project():
        print("错误：Rust 项目编译失败，无法继续测试")
        sys.exit(1)
    
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n输出目录：{OUTPUT_DIR}")
    
    # 处理每个测试用例
    results = []
    success_count = 0
    fail_count = 0
    
    for test_case in test_cases:
        test_id = test_case["id"]
        test_name = test_case["name"]
        plaintext = test_case["plaintext"]
        
        print(f"\n测试用例 {test_id}: {test_name}")
        print(f"  明文：{plaintext[:50]}{'...' if len(plaintext) > 50 else ''}")
        
        try:
            # 执行加密和签名
            result = run_rust_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("Rust 程序执行失败")
            
            ciphertext = result["ciphertext"]
            signature = result["signature"]
            
            # 保存结果
            result_data = {
                "test_case_id": test_id,
                "test_case_name": test_name,
                "plaintext": plaintext,
                "ciphertext_hex": ciphertext,
                "signature_hex": signature
            }
            
            result_file = os.path.join(OUTPUT_DIR, f"test_{test_id}_{test_name}.json")
            save_json_file(result_file, result_data)
            print(f"  密文 (Hex): {ciphertext[:60]}...")
            print(f"  签名 (Hex): {signature[:60]}...")
            print(f"  结果已保存到：{result_file}")
            
            results.append(result_data)
            success_count += 1
            
        except Exception as e:
            print(f"  错误：{e}")
            fail_count += 1
    
    # 保存汇总结果
    summary_data = {
        "summary": {
            "total": len(test_cases),
            "success": success_count,
            "failed": fail_count
        },
        "results": results
    }
    
    summary_file = os.path.join(OUTPUT_DIR, "summary.json")
    save_json_file(summary_file, summary_data)
    print(f"\n汇总结果已保存到：{summary_file}")
    
    # 打印总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    print(f"总测试用例：{len(test_cases)}")
    print(f"成功：{success_count}")
    print(f"失败：{fail_count}")
    if len(test_cases) > 0:
        print(f"成功率：{success_count / len(test_cases) * 100:.1f}%")
    print("=" * 60)
    
    return 0 if fail_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())