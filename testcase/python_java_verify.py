#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python SM2 解密验签互操作性测试脚本

功能：
1. 读取 Java 加密结果从 testcase/results/java_encrypt/
2. 加载密钥从 testcase/keys/java/keys.json
3. 使用 Python SM2Util.decrypt() 和 SM2Util.verify_str() 解密和验签
4. 比较解密后的文本与期望明文
5. 输出结果到 testcase/results/java_verify/python_verify.json
"""

import json
import os
import sys

# 添加 Python crossmool 源码到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python', 'crossmool', 'src'))

from sm2_util import SM2Util, sm2_private_key_to_raw_hex, sm2_public_key_to_raw_hex
from gmssl import sm2

# 配置路径
KEYS_FILE = "testcase/keys/java/keys.json"
JAVA_ENCRYPT_DIR = "testcase/results/java_encrypt"
OUTPUT_DIR = "testcase/results/java_verify"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "python_verify.json")

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def main():
    """主函数"""
    print("=" * 60)
    print("Python SM2 解密验签互操作性测试")
    print("=" * 60)
    
    # 检查密钥文件
    if not os.path.exists(KEYS_FILE):
        print(f"错误：找不到密钥文件：{KEYS_FILE}")
        sys.exit(1)
    
    # 检查 Java 加密结果目录
    if not os.path.exists(JAVA_ENCRYPT_DIR):
        print(f"错误：找不到 Java 加密结果目录：{JAVA_ENCRYPT_DIR}")
        sys.exit(1)
    
    # 加载密钥
    print(f"\n加载密钥：{KEYS_FILE}")
    keys_data = load_json_file(KEYS_FILE)
    
    # 提取密钥
    enc_public_key_hex = keys_data["encryption_public_key"]["hex"]
    sign_private_key_hex = keys_data["signature_private_key"]["hex"]
    # 解密需要私钥，验签需要公钥
    # 注意：Java 生成的密钥对中，加密公钥和签名公钥是同一个
    # 解密使用签名私钥（因为 Java 使用同一个密钥对）
    decrypt_private_key_hex = keys_data["encryption_private_key"]["hex"]
    verify_public_key_hex = keys_data["signature_public_key"]["hex"]
    
    print(f"  加密公钥：{enc_public_key_hex[:40]}...")
    print(f"  解密私钥：{decrypt_private_key_hex[:40]}...")
    print(f"  验签公钥：{verify_public_key_hex[:40]}...")
    
    # [DEBUG] 测试私钥解析
    try:
        raw_priv = sm2_private_key_to_raw_hex(decrypt_private_key_hex)
        print(f"  [DEBUG] 私钥解析结果：{raw_priv[:20] if raw_priv else 'None'}...")
    except Exception as e:
        print(f"  [DEBUG] 私钥解析失败：{e}")
    
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n输出目录：{OUTPUT_DIR}")
    
    # 加载 Java 加密汇总结果
    java_summary_file = os.path.join(JAVA_ENCRYPT_DIR, "summary.json")
    if not os.path.exists(java_summary_file):
        print(f"错误：找不到 Java 加密汇总文件：{java_summary_file}")
        sys.exit(1)
    
    java_summary = load_json_file(java_summary_file)
    java_results = java_summary.get("results", [])
    
    print(f"\nJava 加密结果数量：{len(java_results)}")
    
    # 处理每个测试用例
    verify_results = []
    success_count = 0
    fail_count = 0
    decrypt_success = 0
    verify_success = 0
    
    for java_result in java_results:
        test_id = java_result["test_case_id"]
        test_name = java_result["test_case_name"]
        expected_plaintext = java_result["plaintext"]
        ciphertext_hex = java_result["ciphertext_hex"]
        signature_hex = java_result["signature_hex"]
        
        print(f"\n测试用例 {test_id}: {test_name}")
        print(f"  期望明文：{expected_plaintext[:50]}{'...' if len(expected_plaintext) > 50 else ''}")
        
        result_data = {
            "test_case_id": test_id,
            "test_case_name": test_name,
            "expected_plaintext": expected_plaintext,
            "ciphertext_hex": ciphertext_hex,
            "signature_hex": signature_hex,
            "decrypted_plaintext": None,
            "decrypt_success": False,
            "verify_success": False,
            "plaintext_match": False,
            "error": None
        }
        
        try:
            # 1. 解密
            print(f"  解密中...")
            try:
                # 使用 SM2Util.decrypt_from_hex()，它使用 cipher_mode=1 (C1C3C2 模式)
                # 这与 Java Bouncy Castle 的 SM2Engine.Mode.C1C3C2 匹配
                # 调试：检查私钥格式
                raw_priv = sm2_private_key_to_raw_hex(decrypt_private_key_hex)
                print(f"    [DEBUG] 私钥解析：{raw_priv[:20] if raw_priv else 'None'}...")
                # 传入公钥参数，避免 gmssl 库报错
                decrypted_bytes = SM2Util.decrypt_from_hex(ciphertext_hex, decrypt_private_key_hex, enc_public_key_hex)
                decrypted = decrypted_bytes.decode('utf-8')
                result_data["decrypted_plaintext"] = decrypted
                result_data["decrypt_success"] = True
                decrypt_success += 1
                print(f"    解密成功：{decrypted[:50]}{'...' if len(decrypted) > 50 else ''}")
            except Exception as e:
                result_data["error"] = f"解密失败：{str(e)}"
                print(f"    解密失败：{e}")
                import traceback
                traceback.print_exc()
                fail_count += 1
                verify_results.append(result_data)
                continue
            
            # 2. 验签
            print(f"  验签中...")
            try:
                is_valid = SM2Util.verify_str(expected_plaintext, verify_public_key_hex, signature_hex)
                result_data["verify_success"] = is_valid
                if is_valid:
                    verify_success += 1
                    print(f"    验签成功")
                else:
                    print(f"    验签失败：签名无效")
            except Exception as e:
                result_data["error"] = f"验签失败：{str(e)}"
                print(f"    验签失败：{e}")
                fail_count += 1
                verify_results.append(result_data)
                continue
            
            # 3. 比较明文
            if decrypted == expected_plaintext:
                result_data["plaintext_match"] = True
                success_count += 1
                print(f"    明文匹配：成功")
            else:
                print(f"    明文匹配：失败")
                print(f"      期望：{expected_plaintext}")
                print(f"      实际：{decrypted}")
                fail_count += 1
            
        except Exception as e:
            result_data["error"] = str(e)
            print(f"    错误：{e}")
            fail_count += 1
        
        verify_results.append(result_data)
    
    # 保存汇总结果
    summary_data = {
        "summary": {
            "total": len(java_results),
            "success": success_count,
            "failed": fail_count,
            "decrypt_success": decrypt_success,
            "verify_success": verify_success,
            "success_rate": f"{success_count / len(java_results) * 100:.1f}%" if java_results else "0%"
        },
        "results": verify_results
    }
    
    save_json_file(OUTPUT_FILE, summary_data)
    print(f"\n汇总结果已保存到：{OUTPUT_FILE}")
    
    # 打印总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    print(f"总测试用例：{len(java_results)}")
    print(f"成功：{success_count}")
    print(f"失败：{fail_count}")
    print(f"成功率：{summary_data['summary']['success_rate']}")
    print(f"\n解密成功：{decrypt_success}/{len(java_results)}")
    print(f"验签成功：{verify_success}/{len(java_results)}")
    print(f"明文匹配：{success_count}/{len(java_results)}")
    print("=" * 60)
    
    return 0 if fail_count == 0 else 1

# [SYNC_MARKER] Force file sync to disk
if __name__ == "__main__":
    sys.exit(main())
