#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JavaScript SM2 加密和签名互操作性测试脚本

功能：
1. 读取 testcase/keys/javascript/keys.json 中的密钥
2. 读取 testcase/test_data.json 中的测试数据
3. 通过 Node.js 调用 javascript/crossmool/dist 中的模块执行加密和签名操作
4. 输出 Hex 格式的密文和签名到 testcase/results/javascript_encrypt 目录
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# 配置路径
NODE_EXECUTABLE = "node"
DIST_PATH = "javascript/crossmool/dist"
KEYS_FILE = "testcase/keys/javascript/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/javascript_encrypt"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_javascript_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    """
    运行 Node.js 脚本执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 创建临时 JavaScript 文件
    temp_js_file = "temp_sm2_test.js"
    
    # 转义内容中的特殊字符
    escaped_content = content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t').replace('\r', '\\r')
    
    js_code = f'''
const {{ SM2Util }} = require('{DIST_PATH.replace("/", "/")}/index.js');

const content = "{escaped_content}";
const encPublicKey = "{enc_public_key_hex}";
const signPrivateKey = "{sign_private_key_hex}";

try {{
    const result = SM2Util.encryptSign(content, encPublicKey, signPrivateKey, false);
    console.log(result.ciphertext + "\\t" + result.signature);
}} catch (error) {{
    console.error("ERROR:" + error.message);
    process.exit(1);
}}
'''
    
    with open(temp_js_file, 'w', encoding='utf-8') as f:
        f.write(js_code)
    
    try:
        # 运行 Node.js 脚本
        run_result = subprocess.run(
            [NODE_EXECUTABLE, temp_js_file],
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        
        if run_result.returncode != 0:
            print(f"运行失败：{run_result.stderr}")
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
            print(f"输出格式错误：{output}")
            return None
            
    finally:
        # 清理临时文件
        if os.path.exists(temp_js_file):
            os.remove(temp_js_file)

def main():
    """主函数"""
    print("=" * 60)
    print("JavaScript SM2 加密和签名互操作性测试")
    print("=" * 60)
    
    # 检查 Node.js 可执行文件
    try:
        subprocess.run([NODE_EXECUTABLE, "--version"], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        print(f"错误：找不到 Node.js 可执行文件：{NODE_EXECUTABLE}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"错误：找不到 Node.js 可执行文件：{NODE_EXECUTABLE}")
        sys.exit(1)
    
    # 检查 dist 目录
    if not os.path.exists(DIST_PATH):
        print(f"错误：找不到 dist 目录：{DIST_PATH}")
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
            result = run_javascript_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("Node.js 脚本执行失败")
            
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