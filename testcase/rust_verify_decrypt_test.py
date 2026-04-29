#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rust 语言 SM2 解密验签互操作性测试脚本

功能：
1. 读取 testcase/keys/rust/keys.json 中的解密私钥和验签公钥
2. 读取其他语言加密生成的密文和签名 JSON 文件
3. 调用已编译的 Rust 程序执行 SM2 验签和解密操作
4. 输出验证和解密结果到 testcase/results/rust_verify 目录
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
OUTPUT_DIR = "testcase/results/rust_verify"

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

def run_rust_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    """
    创建临时 Rust 程序执行验签和解密
    
    参数:
        ciphertext_hex: 密文 (Hex 格式)
        signature_hex: 签名 (Hex 格式)
        sign_public_key_hex: 验签公钥 (Hex 格式)
        dec_private_key_hex: 解密私钥 (Hex 格式)
    
    返回:
        tuple: (success: bool, decrypted_text: str or error_message: str)
    """
    # 将 Hex 密钥转换为 PEM 格式
    public_pem = hex_to_base64_pem(sign_public_key_hex, "PUBLIC KEY")
    private_pem = hex_to_base64_pem(dec_private_key_hex, "PRIVATE KEY")
    
    # 转义 Rust 字符串中的特殊字符
    ciphertext_escaped = ciphertext_hex.replace('\\', '\\\\').replace('"', '\\"')
    signature_escaped = signature_hex.replace('\\', '\\\\').replace('"', '\\"')
    public_pem_escaped = public_pem.replace('\\', '\\\\').replace('"', '\\"')
    private_pem_escaped = private_pem.replace('\\', '\\\\').replace('"', '\\"')
    
    # 创建临时 Rust 程序，调用 verify_with_public_pem 和 decrypt_with_private_pem_hex
    rust_code = f'''use std::process;

fn main() {{
    let ciphertext_hex = "{ciphertext_escaped}";
    let signature_hex = "{signature_escaped}";
    let public_pem = r#"{public_pem_escaped}"#;
    let private_pem = r#"{private_pem_escaped}"#;
    
    // 先验签：需要先解密得到明文，然后用明文验签
    // 但由于我们不知道明文，所以先解密，再验签
    
    // 解密
    match crossmool::sm2::decrypt_with_private_pem_hex(&private_pem, &ciphertext_hex) {{
        Ok(plaintext_bytes) => {{
            // 将签名 Hex 转为 bytes
            let signature_bytes = match hex::decode(&signature_hex) {{
                Ok(sig) => sig,
                Err(e) => {{
                    eprintln!("ERROR:签名 Hex 解码失败：{{}}", e);
                    process::exit(1);
                }}
            }};
            
            // 验签
            match crossmool::sm2::verify_with_public_pem(&plaintext_bytes, &signature_bytes, &public_pem) {{
                Ok(true) => {{
                    // 验签成功，输出解密后的明文
                    match String::from_utf8(plaintext_bytes) {{
                        Ok(text) => println!("SUCCESS:{{}}", text),
                        Err(e) => {{
                            eprintln!("ERROR:UTF-8 解码失败：{{}}", e);
                            process::exit(1);
                        }}
                    }}
                }}
                Ok(false) => {{
                    eprintln!("ERROR:验签失败");
                    process::exit(1);
                }}
                Err(e) => {{
                    eprintln!("ERROR:验签错误：{{}}", e);
                    process::exit(1);
                }}
            }}
        }}
        Err(e) => {{
            eprintln!("ERROR:解密失败：{{}}", e);
            process::exit(1);
        }}
    }}
}}
'''
    
    # 创建临时目录
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_project = os.path.join(temp_dir, "rust_verify_temp")
        os.makedirs(temp_project)
        
        # 创建 Cargo.toml
        cargo_toml_content = '''[package]
name = "rust_verify_temp"
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
            build_result = subprocess.run(
                ["cargo", "build", "--release"],
                cwd=temp_project,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if build_result.returncode != 0:
                return False, f"Rust 程序编译失败：{build_result.stderr}"
            
            # 运行程序
            exe_name = "rust_verify_temp"
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
                error_msg = run_result.stderr.strip()
                if "ERROR:" in error_msg:
                    error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
                return False, error_msg
            
            output = run_result.stdout.strip()
            if output.startswith("SUCCESS:"):
                decrypted_text = output[8:]  # 去掉 "SUCCESS:" 前缀
                return True, decrypted_text
            else:
                return False, f"未知输出格式：{output}"
            
        except subprocess.TimeoutExpired:
            return False, "Rust 程序执行超时"
        except Exception as e:
            return False, f"Rust 程序调用异常：{e}"

def verify_language_results(language, output_dir):
    """
    验证指定语言的加密结果
    
    参数:
        language: 语言名称 (c, cpp, csharp, golang, java, javascript, python, rust)
        output_dir: 该语言的加密结果目录
    
    返回:
        dict: 验证结果统计
    """
    results = []
    success_count = 0
    fail_count = 0
    
    # 加载 Rust 密钥
    keys = load_json_file(KEYS_FILE)
    sign_public_key_hex = keys["encryption_public_key"]["hex"]
    dec_private_key_hex = keys["signature_private_key"]["hex"]
    
    # 遍历加密结果目录
    if not os.path.exists(output_dir):
        print(f"\n警告：加密结果目录不存在：{output_dir}")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    json_files = sorted(Path(output_dir).glob("test_*.json"))
    
    if not json_files:
        print(f"\n警告：在 {output_dir} 中未找到测试用例文件")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    print(f"\n找到 {len(json_files)} 个加密结果文件")
    
    for json_file in json_files:
        # 跳过汇总文件
        if json_file.name.startswith("summary"):
            continue
        
        try:
            result_data = load_json_file(str(json_file))
            test_id = result_data.get("test_case_id", "unknown")
            test_name = result_data.get("test_case_name", "unknown")
            expected_plaintext = result_data.get("plaintext", "")
            ciphertext_hex = result_data.get("ciphertext_hex", "")
            signature_hex = result_data.get("signature_hex", "")
            
            print(f"\n  测试用例 {test_id}: {test_name}")
            print(f"    来源语言：{language}")
            print(f"    密文 (Hex): {ciphertext_hex[:60]}...")
            
            # 执行验签和解密
            success, decrypted_or_error = run_rust_verify_decrypt(
                ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex
            )
            
            if success:
                # 验证解密结果是否与原始明文一致
                if decrypted_or_error == expected_plaintext:
                    print(f"    ✓ 验签成功，解密结果匹配")
                    print(f"    解密文本：{decrypted_or_error[:50]}{'...' if len(decrypted_or_error) > 50 else ''}")
                    success_count += 1
                    result_entry = {
                        "test_case_id": test_id,
                        "test_case_name": test_name,
                        "source_language": language,
                        "status": "success",
                        "expected_plaintext": expected_plaintext,
                        "decrypted_text": decrypted_or_error,
                        "match": True
                    }
                else:
                    print(f"    ✗ 验签成功，但解密结果不匹配")
                    print(f"    期望：{expected_plaintext[:50]}{'...' if len(expected_plaintext) > 50 else ''}")
                    print(f"    实际：{decrypted_or_error[:50]}{'...' if len(decrypted_or_error) > 50 else ''}")
                    fail_count += 1
                    result_entry = {
                        "test_case_id": test_id,
                        "test_case_name": test_name,
                        "source_language": language,
                        "status": "mismatch",
                        "expected_plaintext": expected_plaintext,
                        "decrypted_text": decrypted_or_error,
                        "match": False
                    }
            else:
                print(f"    ✗ 验签失败：{decrypted_or_error}")
                fail_count += 1
                result_entry = {
                    "test_case_id": test_id,
                    "test_case_name": test_name,
                    "source_language": language,
                    "status": "failed",
                    "error": decrypted_or_error,
                    "expected_plaintext": expected_plaintext,
                    "match": False
                }
            
            results.append(result_entry)
            
        except Exception as e:
            print(f"\n  处理文件 {json_file.name} 时出错：{e}")
            fail_count += 1
    
    return {
        "total": len(json_files),
        "success": success_count,
        "failed": fail_count,
        "results": results
    }

def main():
    """主函数"""
    print("=" * 70)
    print("Rust SM2 解密验签互操作性测试")
    print("=" * 70)
    
    # 检查 Rust 项目
    if not os.path.exists(RUST_PROJECT_PATH):
        print(f"错误：找不到 Rust 项目目录：{RUST_PROJECT_PATH}")
        sys.exit(1)
    
    # 检查密钥文件
    if not os.path.exists(KEYS_FILE):
        print(f"错误：找不到密钥文件：{KEYS_FILE}")
        sys.exit(1)
    
    # 加载密钥
    print(f"\n加载密钥文件：{KEYS_FILE}")
    keys = load_json_file(KEYS_FILE)
    sign_public_key_hex = keys["encryption_public_key"]["hex"]
    dec_private_key_hex = keys["signature_private_key"]["hex"]
    print(f"  验签公钥 (Hex): {sign_public_key_hex[:40]}...")
    print(f"  解密私钥 (Hex): {dec_private_key_hex[:40]}...")
    
    # 定义要测试的语言及其加密结果目录
    languages = [
        ("c", "testcase/results/c_encrypt"),
        ("cpp", "testcase/results/cpp_encrypt"),
        ("csharp", "testcase/results/csharp_encrypt"),
        ("golang", "testcase/results/golang_encrypt"),
        ("java", "testcase/results/java_encrypt"),
        ("javascript", "testcase/results/javascript_encrypt"),
        ("python", "testcase/results/python_encrypt"),
        ("rust", "testcase/results/rust_encrypt"),
    ]
    
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n验证结果输出目录：{OUTPUT_DIR}")
    
    # 处理每种语言
    all_results = {}
    total_tests = 0
    total_success = 0
    total_failed = 0
    
    for language, encrypt_dir in languages:
        print(f"\n{'=' * 70}")
        print(f"验证 {language.upper()} 语言的加密结果")
        print(f"{'=' * 70}")
        
        lang_result = verify_language_results(language, encrypt_dir)
        all_results[language] = lang_result
        
        total_tests += lang_result["total"]
        total_success += lang_result["success"]
        total_failed += lang_result["failed"]
        
        # 保存该语言的验证结果
        if lang_result["total"] > 0:
            lang_output_file = os.path.join(OUTPUT_DIR, f"{language}_verify_summary.json")
            save_json_file(lang_output_file, lang_result)
            print(f"\n  {language} 语言验证结果已保存到：{lang_output_file}")
            print(f"  总计：{lang_result['total']}, 成功：{lang_result['success']}, 失败：{lang_result['failed']}")
    
    # 保存汇总结果
    summary_data = {
        "summary": {
            "total": total_tests,
            "success": total_success,
            "failed": total_failed,
            "success_rate": f"{total_success / total_tests * 100:.1f}%" if total_tests > 0 else "0%"
        },
        "languages": all_results
    }
    
    summary_file = os.path.join(OUTPUT_DIR, "summary.json")
    save_json_file(summary_file, summary_data)
    print(f"\n汇总结果已保存到：{summary_file}")
    
    # 打印总结
    print("\n" + "=" * 70)
    print("测试总结")
    print("=" * 70)
    print(f"总测试用例：{total_tests}")
    print(f"成功：{total_success}")
    print(f"失败：{total_failed}")
    if total_tests > 0:
        print(f"成功率：{total_success / total_tests * 100:.1f}%")
    print("=" * 70)
    
    return 0 if total_failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())