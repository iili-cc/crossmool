#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""调试脚本 - 直接输出到控制台"""

import json
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path

# 添加 Python 实现路径
sys.path.insert(0, str(Path(__file__).parent.parent / 'python' / 'crossmool' / 'src'))

print("=" * 60)
print("Java-Python SM2 互通测试调试脚本")
print("=" * 60)
print()

# 路径配置
KEYS_FILE = 'testcase/keys/java/keys.json'
JAVA_ENCRYPT_DIR = 'testcase/results/java_encrypt'

def main():
    try:
        print("步骤 1: 尝试导入 SM2Util...")
        from sm2_util import SM2Util
        print("✓ SM2Util 导入成功")
        print()
        
        print("步骤 2: 加载 Java 密钥...")
        with open(KEYS_FILE, 'r', encoding='utf-8') as f:
            keys = json.load(f)
        
        encryption_private_key = keys['encryption_private_key']['hex']
        signature_public_key = keys['signature_public_key']['hex']
        
        print(f"  加密私钥 (前 40 字符): {encryption_private_key[:40]}...")
        print(f"  签名公钥 (前 40 字符): {signature_public_key[:40]}...")
        print("✓ 密钥加载成功")
        print()
        
        print("步骤 3: 加载测试用例...")
        test_file = Path(JAVA_ENCRYPT_DIR) / 'test_1_simple_text.json'
        with open(test_file, 'r', encoding='utf-8') as f:
            test_case = json.load(f)
        
        print(f"  测试用例：{test_case['test_case_name']}")
        print(f"  原文：{test_case['plaintext']}")
        print(f"  密文 (前 40 字符): {test_case['ciphertext_hex'][:40]}...")
        print(f"  签名 (前 40 字符): {test_case['signature_hex'][:40]}...")
        print("✓ 测试用例加载成功")
        print()
        
        print("步骤 4: 尝试解密...")
        try:
            decrypted_bytes = SM2Util.decrypt_from_hex(
                test_case['ciphertext_hex'],
                encryption_private_key
            )
            decrypted_text = decrypted_bytes.decode('utf-8')
            print(f"✓ 解密成功：{decrypted_text}")
            
            if decrypted_text == test_case['plaintext']:
                print("✓ 解密结果与原文匹配")
            else:
                print("✗ 解密结果与原文不匹配")
                print(f"  原文：{test_case['plaintext']}")
                print(f"  解密：{decrypted_text}")
        except Exception as e:
            print(f"✗ 解密失败：{e}")
            traceback.print_exc()
        print()
        
        print("步骤 5: 尝试验签...")
        try:
            original_bytes = test_case['plaintext'].encode('utf-8')
            verify_result = SM2Util.verify(
                original_bytes,
                signature_public_key,
                test_case['signature_hex']
            )
            if verify_result:
                print("✓ 验签成功")
            else:
                print("✗ 验签失败：签名不匹配")
        except Exception as e:
            print(f"✗ 验签失败：{e}")
            traceback.print_exc()
        print()
        
        print("=" * 60)
        print("调试完成")
        print("=" * 60)
        
    except Exception as e:
        print(f"错误：{e}")
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())