#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Go 语言 SM2 加密和签名互操作性测试脚本

功能:
1. 读取 testcase/keys/golang/keys.json 中的密钥
2. 读取 testcase/test_data.json 中的测试数据
3. 调用 Go 程序执行加密和签名操作
4. 输出 Hex 格式的密文和签名到 testcase/results/golang_encrypt 目录
"""

import json
import os
import sys
import subprocess
from pathlib import Path

# 配置路径
GO_MODULE_PATH = "golang/crossmool"
KEYS_FILE = "testcase/keys/golang/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/golang_encrypt"
TEMP_DIR = "testcase/.golang_temp"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_golang_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    """
    通过 go run 命令调用 Go 程序执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 创建临时目录
    temp_path = Path(TEMP_DIR)
    temp_path.mkdir(exist_ok=True)
    
    # 创建临时 Go 测试文件
    test_file = temp_path / "sm2_interop_test.go"
    
    # 将内容写入临时文件以避免转义问题
    content_file = temp_path / "input_content.txt"
    content_file.write_text(content, encoding='utf-8')
    
    # 创建 Go 测试程序
    go_code = f'''package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"crossmool"
)

type Result struct {{
	CiphertextHex string `json:"ciphertext_hex"`
	SignatureHex  string `json:"signature_hex"`
}}

func main() {{
	// 读取输入内容
	content, err := ioutil.ReadFile("input_content.txt")
	if err != nil {{
		fmt.Fprintf(os.Stderr, "Error reading input: %v\\n", err)
		os.Exit(1)
	}}

	encPublicKey := "{enc_public_key_hex}"
	signPrivateKey := "{sign_private_key_hex}"

	// 执行加密和签名
	pair, err := crossmool.EncryptSignDefault(string(content), encPublicKey, signPrivateKey)
	if err != nil {{
		fmt.Fprintf(os.Stderr, "Error encryptSign: %v\\n", err)
		os.Exit(1)
	}}

	result := Result{{
		CiphertextHex: pair.Ciphertext,
		SignatureHex:  pair.Signature,
	}}

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {{
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\\n", err)
		os.Exit(1)
	}}

	fmt.Println(string(jsonData))
}}
'''
    test_file.write_text(go_code, encoding='utf-8')
    
    try:
        # 创建临时的 go.mod 文件
        go_mod_file = temp_path / "go.mod"
        go_mod_content = '''module sm2test

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
            print(f"  Go 程序执行失败:\n{run_result.stderr}")
            return None
        
        # 解析输出
        output_json = run_result.stdout.strip()
        result_data = json.loads(output_json)
        
        ciphertext_hex = result_data.get("ciphertext_hex")
        signature_hex = result_data.get("signature_hex")
        
        if ciphertext_hex is None or signature_hex is None:
            print(f"  加密签名结果解析失败：{output_json}")
            return None
        
        return {
            "ciphertext": ciphertext_hex,
            "signature": signature_hex
        }
        
    except subprocess.TimeoutExpired:
        print("  Go 程序执行超时")
        return None
    except Exception as e:
        print(f"  Go 程序调用异常：{e}")
        return None
    finally:
        # 清理临时目录
        try:
            if temp_path.exists():
                import shutil
                shutil.rmtree(temp_path)
        except:
            pass

def main():
    """主函数"""
    print("=" * 60)
    print("Go 语言 SM2 加密和签名互操作性测试")
    print("=" * 60)
    
    # 检查 Go 模块
    if not os.path.exists(GO_MODULE_PATH):
        print(f"错误：找不到 Go 模块目录：{GO_MODULE_PATH}")
        sys.exit(1)
    
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
            result = run_golang_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("Go 程序调用失败")
            
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
    print(f"成功率：{success_count / len(test_cases) * 100:.1f}%")
    print("=" * 60)
    
    return 0 if fail_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())