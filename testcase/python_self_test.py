#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python SM2 自测试 - 验证加密解密、签名验签的自洽性
"""

import sys
import json
from pathlib import Path

# 添加 src 目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent / 'python' / 'crossmool' / 'src'))

from sm2 import SM2Util, SM2KeyUtil

# 测试密钥 (与 Java 相同)
ENCRYPTION_PUBLIC_KEY = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"
ENCRYPTION_PRIVATE_KEY = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

SIGNATURE_PUBLIC_KEY = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"
SIGNATURE_PRIVATE_KEY = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

def test_encrypt_decrypt():
    """测试加密解密"""
    print("=" * 60)
    print("测试 1: 加密解密")
    print("=" * 60)
    
    util = SM2Util(
        encryption_pub_key=ENCRYPTION_PUBLIC_KEY,
        encryption_priv_key=ENCRYPTION_PRIVATE_KEY
    )
    
    test_texts = [
        "Hello, Crossmool!",
        "你好，世界！",
        "Test 123",
        "A" * 100,
        "你好，我是 SM2 算法测试数据，包括简体中文，繁体中文，English 三种文字，you can use me for a test!"
    ]
    
    all_passed = True
    for i, plaintext in enumerate(test_texts, 1):
        try:
            # 加密
            ciphertext = util.encrypt(plaintext)
            print(f"\n测试 {i}: {plaintext[:30]}{'...' if len(plaintext) > 30 else ''}")
            print(f"  密文长度：{len(ciphertext) // 2} 字节")
            
            # 解密
            decrypted = util.decrypt(ciphertext)
            print(f"  解密结果：{decrypted[:30]}{'...' if len(decrypted) > 30 else ''}")
            
            # 验证
            if decrypted == plaintext:
                print(f"  [PASS]")
            else:
                print(f"  [FAIL]: 解密结果与原文不匹配")
                all_passed = False
        except Exception as e:
            print(f"  [ERROR]: {e}")
            all_passed = False
    
    return all_passed

def test_sign_verify():
    """测试签名验签"""
    print("\n" + "=" * 60)
    print("测试 2: 签名验签")
    print("=" * 60)
    
    util = SM2Util(
        signature_pub_key=SIGNATURE_PUBLIC_KEY,
        signature_priv_key=SIGNATURE_PRIVATE_KEY
    )
    
    test_texts = [
        "Hello, Crossmool!",
        "你好，世界！",
        "Test 123",
        "A" * 100,
    ]
    
    all_passed = True
    for i, content in enumerate(test_texts, 1):
        try:
            # 签名
            signature = util.sign(content)
            print(f"\n测试 {i}: {content[:30]}{'...' if len(content) > 30 else ''}")
            print(f"  签名长度：{len(signature) // 2} 字节")
            
            # 验签
            is_valid = util.verify(content, signature)
            print(f"  验签结果：{'[PASS]' if is_valid else '[FAIL]'}")
            
            if not is_valid:
                all_passed = False
            
            # 测试篡改内容
            tampered = content + "X"
            is_invalid = not util.verify(tampered, signature)
            print(f"  篡改检测：{'[PASS]' if is_invalid else '[FAIL]'}")
            
            if not is_invalid:
                all_passed = False
                
        except Exception as e:
            print(f"  [ERROR]: {e}")
            all_passed = False
    
    return all_passed

def test_key_parsing():
    """测试密钥解析"""
    print("\n" + "=" * 60)
    print("测试 3: 密钥解析")
    print("=" * 60)
    
    try:
        # 解析公钥
        pub_raw = SM2KeyUtil.parse_x509_public_key(
            SM2KeyUtil.convert_string_to_bytes(ENCRYPTION_PUBLIC_KEY)
        )
        print(f"\n公钥解析:")
        print(f"  原始公钥：{pub_raw}")
        print(f"  长度：{len(pub_raw) // 2} 字节 (期望 65 字节)")
        
        if len(pub_raw) != 130:  # 65 字节 = 130 hex 字符
            print(f"  [FAIL]: 公钥长度不正确")
            return False
        print(f"  [PASS]")
        
        # 解析私钥
        priv_raw = SM2KeyUtil.parse_pkcs8_private_key(
            SM2KeyUtil.convert_string_to_bytes(ENCRYPTION_PRIVATE_KEY)
        )
        print(f"\n私钥解析:")
        print(f"  原始私钥：{priv_raw}")
        print(f"  长度：{len(priv_raw) // 2} 字节 (期望 32 字节)")
        
        if len(priv_raw) != 64:  # 32 字节 = 64 hex 字符
            print(f"  [FAIL]: 私钥长度不正确")
            return False
        print(f"  [PASS]")
        
        return True
        
    except Exception as e:
        print(f"  [ERROR]: {e}")
        return False

def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("Python SM2 自测试")
    print("=" * 60)
    
    results = []
    
    # 测试密钥解析
    results.append(("密钥解析", test_key_parsing()))
    
    # 测试加密解密
    results.append(("加密解密", test_encrypt_decrypt()))
    
    # 测试签名验签
    results.append(("签名验签", test_sign_verify()))
    
    # 总结
    print("\n" + "=" * 60)
    print("测试结果总结")
    print("=" * 60)
    
    all_passed = True
    for test_name, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("所有测试通过！")
    else:
        print("部分测试失败！")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())