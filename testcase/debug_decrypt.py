#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试解密问题：对比 Java 和 Python 的解密过程
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'python' / 'crossmool' / 'src'))

from sm2_util import sm2_private_key_to_raw_hex, sm2_public_key_to_raw_hex, SM2Util
from gmssl import sm2, sm3

# 加载密钥
keys_file = Path('testcase/keys/java/keys.json')
with open(keys_file, 'r', encoding='utf-8') as f:
    keys = json.load(f)

priv_hex = sm2_private_key_to_raw_hex(keys['encryption_private_key']['hex'])
pub_hex = sm2_public_key_to_raw_hex(keys['encryption_public_key']['hex'])

print(f"私钥 (raw): {priv_hex}")
print(f"公钥 (raw): {pub_hex}")

# 加载测试用例
test_file = Path('testcase/results/java_encrypt/test_1_simple_text.json')
with open(test_file, 'r', encoding='utf-8') as f:
    test = json.load(f)

cipher_hex = test['ciphertext_hex']
plaintext = test['plaintext']

print(f"\n明文：{plaintext}")
print(f"密文 (HEX): {cipher_hex}")
print(f"密文长度：{len(cipher_hex)//2} 字节")

# 解析 C1C3C2 格式
c1 = cipher_hex[0:130]  # 65 字节
c3 = cipher_hex[130:194]  # 32 字节
c2 = cipher_hex[194:]  # 变长

print(f"\nC1: {c1}")
print(f"C3: {c3}")
print(f"C2: {c2}")

# 手动解密
print("\n=== 手动解密 ===")
crypt = sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, mode=1)

# 从 C1 和私钥恢复共享密钥
c1_bytes = bytes.fromhex(c1)
print(f"C1 bytes: {c1_bytes.hex()}")

# 解密
try:
    decrypted = crypt.decrypt(bytes.fromhex(cipher_hex))
    print(f"解密结果 (bytes): {decrypted}")
    print(f"解密结果 (hex): {decrypted.hex()}")
    try:
        print(f"解密结果 (utf-8): {decrypted.decode('utf-8')}")
    except:
        print("无法解码为 UTF-8")
except Exception as e:
    print(f"解密失败：{e}")

# 验证 gmssl 加密是否自洽
print("\n=== 验证 gmssl 自加密自解密 ===")
test_msg = plaintext.encode('utf-8')
encrypted = SM2Util.encrypt_to_hex(test_msg, pub_hex)
print(f"加密结果：{encrypted}")

decrypted2 = SM2Util.decrypt_from_hex(encrypted, priv_hex, pub_hex)
print(f"解密结果：{decrypted2}")
print(f"解密结果 (utf-8): {decrypted2.decode('utf-8')}")
print(f"与原文匹配：{decrypted2 == test_msg}")