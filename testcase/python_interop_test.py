#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python SM2 加密和签名互操作性测试脚本

功能：
1. 读取 testcase/keys/python/keys.json 中的密钥
2. 读取 testcase/test_data.json 中的测试数据
3. 直接导入 python/crossmool/src/crossmool 模块执行 SM2 加密和签名操作
4. 输出 Hex 格式的密文和签名到 testcase/results/python_encrypt 目录
"""

import json
import os
import sys
from pathlib import Path

# 添加 Python 模块路径 - 使用绝对路径
SCRIPT_DIR = Path(__file__).parent.parent
PYTHON_MODULE_PATH = SCRIPT_DIR / "python" / "crossmool" / "src"
if str(PYTHON_MODULE_PATH) not in sys.path:
    sys.path.insert(0, str(PYTHON_MODULE_PATH))

try:
    from sm2_util import SM2Util
except ImportError as e:
    print(f"错误：无法导入 sm2_util 模块：{e}")
    print(f"Python 路径：{sys.path}")
    print(f"尝试从：{PYTHON_MODULE_PATH}")
    sys.exit(1)

# 配置路径
KEYS_FILE = "testcase/keys/python/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/python_encrypt"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_python_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    """
    使用 Python SM2Util 执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    try:
        # 执行加密
        ciphertext_hex = SM2Util.encrypt(content, enc_public_key_hex, to_base64=False)
        
        # 执行签名
        signature_hex = SM2Util.sign(content, sign_private_key_hex, to_base64=False)
        
        return {
            "ciphertext": ciphertext_hex,
            "signature": signature_hex
        }
    except Exception as e:
        print(f"加密签名错误：{e}")
        return None

def main():
    """主函数"""
    print("=" * 60)
    print("Python SM2 加密和签名互操作性测试")
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
            result = run_python_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("Python SM2Util 执行失败")
            
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