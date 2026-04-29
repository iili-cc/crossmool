#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C++ 语言 SM2 加密和签名互操作性测试脚本

功能：
1. 读取 testcase/keys/cpp/keys.json 中的密钥
2. 读取 testcase/test_data.json 中的测试数据
3. 调用 C++ 可执行文件 (interoperability_test.exe) 执行加密和签名操作
4. 输出 Hex 格式的密文和签名到 testcase/results/cpp_encrypt 目录
"""

import json
import os
import sys
import subprocess
from pathlib import Path

# 配置路径
EXE_PATH = "cpp/crossmool/build/bin/Release/interoperability_test.exe"
KEYS_FILE = "testcase/keys/cpp/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/cpp_encrypt"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_cpp_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex, exe_path):
    """
    调用 C++ 可执行文件执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
        exe_path: C++ 可执行文件路径
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 创建临时文件存储输入数据
    temp_dir = Path("testcase/.cpp_temp")
    temp_dir.mkdir(exist_ok=True)
    
    input_file = temp_dir / "input.txt"
    keys_file = temp_dir / "keys.json"
    output_file = temp_dir / "output.json"
    
    # 写入输入内容
    with open(input_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    # 写入密钥文件 - C++ 程序从单个 JSON 文件中读取两个 hex 字段
    # 第一个 hex 作为加密公钥，第二个 hex 作为签名私钥
    # 由于 extractJsonValue 只返回第一个匹配的"hex"值，需要特殊处理
    # 将公钥和私钥放在同一个 JSON 文件中，用不同的键名
    combined_keys = {
        "encryption_public_key": {"hex": enc_public_key_hex},
        "signature_private_key": {"hex": sign_private_key_hex}
    }
    with open(keys_file, 'w', encoding='utf-8') as f:
        json.dump(combined_keys, f)
    
    # 构建命令行参数
    # 调用方式：interoperability_test.exe encrypt_sign <input_file> <keys_file> <output_file>
    cmd = [
        exe_path,
        "encrypt_sign",
        str(input_file),
        str(keys_file),
        str(output_file)
    ]
    
    try:
        # 执行 C++ 可执行文件
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=30,
            errors='replace'  # 替换无法解码的字符
        )
        
        if result.returncode != 0:
            # 尝试获取 stderr（Python 3.7+ 可能直接返回 str）
            stderr_output = result.stderr
            if isinstance(stderr_output, bytes):
                stderr_output = stderr_output.decode('utf-8', errors='replace')
            elif stderr_output is None:
                stderr_output = "无错误输出"
            print(f"  C++ 程序执行失败 (返回码：{result.returncode})")
            print(f"  错误输出：{stderr_output}")
            return None
        
        # 检查输出文件是否存在
        if not output_file.exists():
            print(f"  输出文件未生成：{output_file}")
            return None
        
        # 读取输出结果
        with open(output_file, 'r', encoding='utf-8') as f:
            output_data = json.load(f)
        
        ciphertext_hex = output_data.get("ciphertext_hex")
        signature_hex = output_data.get("signature_hex")
        
        if ciphertext_hex is None or signature_hex is None:
            print("  加密签名结果解析失败")
            return None
        
        return {
            "ciphertext": ciphertext_hex,
            "signature": signature_hex
        }
        
    except subprocess.TimeoutExpired:
        print("  C++ 程序执行超时")
        return None
    except Exception as e:
        print(f"  C++ 程序调用异常：{e}")
        return None
    finally:
        # 清理临时文件
        try:
            if input_file.exists():
                input_file.unlink()
            if keys_file.exists():
                keys_file.unlink()
            if output_file.exists():
                output_file.unlink()
        except:
            pass

def main():
    """主函数"""
    print("=" * 60)
    print("C++ 语言 SM2 加密和签名互操作性测试")
    print("=" * 60)
    
    # 检查可执行文件
    if not os.path.exists(EXE_PATH):
        print(f"错误：找不到可执行文件：{EXE_PATH}")
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
            result = run_cpp_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex, EXE_PATH)
            
            if result is None:
                raise Exception("C++ 可执行文件调用失败")
            
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