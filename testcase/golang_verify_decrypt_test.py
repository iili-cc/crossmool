#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Go 语言 SM2 解密验签互操作性测试脚本

功能：
1. 读取 testcase/keys/golang/keys.json 中的解密私钥和验签公钥
2. 读取其他语言加密生成的密文和签名 JSON 文件
3. 调用 Go 程序执行 SM2 验签和解密操作
4. 输出验证和解密结果到 testcase/results/golang_verify 目录
"""

import json
import os
import sys
import subprocess
from pathlib import Path

# 配置路径
GO_MODULE_PATH = "golang/crossmool"
KEYS_FILE = "testcase/keys/golang/keys.json"
OUTPUT_DIR = "testcase/results/golang_verify"
TEMP_DIR = "testcase/.golang_verify_temp"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_golang_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    """
    通过 go run 命令调用 Go 程序执行验签和解密
    
    参数:
        ciphertext_hex: 密文 (Hex 格式)
        signature_hex: 签名 (Hex 格式)
        sign_public_key_hex: 验签公钥 (Hex 格式)
        dec_private_key_hex: 解密私钥 (Hex 格式)
    
    返回:
        tuple: (success: bool, decrypted_text: str or error_message: str)
    """
    # 创建临时目录
    temp_path = Path(TEMP_DIR)
    temp_path.mkdir(exist_ok=True)
    
    # 创建临时 Go 测试文件
    test_file = temp_path / "sm2_verify_test.go"
    
    # 创建 Go 测试程序，调用 VerifyDecrypt 函数
    go_code = f'''package main

import (
	"fmt"
	"os"
)

func main() {{
	ciphertext := "{ciphertext_hex}"
	signature := "{signature_hex}"
	signPublicKey := "{sign_public_key_hex}"
	decPrivateKey := "{dec_private_key_hex}"
	
	// 执行验签和解密
	plaintext, err := crossmool.VerifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)
	if err != nil {{
		fmt.Fprintf(os.Stderr, "ERROR:%v\\n", err)
		os.Exit(1)
	}}
	
	fmt.Printf("SUCCESS:%s\\n", plaintext)
}}
'''
    test_file.write_text(go_code, encoding='utf-8')
    
    try:
        # 创建临时的 go.mod 文件
        go_mod_file = temp_path / "go.mod"
        go_mod_content = '''module verifytest

go 1.21

replace crossmool => ../golang/crossmool

require crossmool v0.0.0
'''
        go_mod_file.write_text(go_mod_content, encoding='utf-8')
        
        # 运行 Go 程序
        run_result = subprocess.run(
            ["go", "run", str(test_file)],
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='replace',
            cwd=str(temp_path)
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
        return False, "Go 程序执行超时"
    except Exception as e:
        return False, f"Go 程序调用异常：{e}"
    finally:
        # 清理临时目录
        try:
            if temp_path.exists():
                import shutil
                shutil.rmtree(temp_path)
        except:
            pass

def verify_language_results(language, output_dir):
    """
    验证指定语言的加密结果
    
    参数:
        language: 语言名称 (c, cpp, csharp, java, javascript, python, rust)
        output_dir: 该语言的加密结果目录
    
    返回:
        dict: 验证结果统计
    """
    results = []
    success_count = 0
    fail_count = 0
    
    # 加载 Go 密钥
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
            success, decrypted_or_error = run_golang_verify_decrypt(
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
    print("Go SM2 解密验签互操作性测试")
    print("=" * 70)
    
    # 检查 Go 模块
    if not os.path.exists(GO_MODULE_PATH):
        print(f"错误：找不到 Go 模块目录：{GO_MODULE_PATH}")
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