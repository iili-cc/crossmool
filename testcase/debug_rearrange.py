#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试重新排列密文后解密
"""

import json
from pathlib import Path
from gmssl import sm2

# 加载密钥
keys_file = Path('testcase/keys/java/keys.json')
with open(keys_file, 'r', encoding='utf-8') as f:
    keys = json.load(f)

priv_hex = "72e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057"
pub_hex = "048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

# 加载测试用例
test_file = Path('testcase/results/java_encrypt/test_1_simple_text.json')
with open(test_file, 'r', encoding='utf-8') as f:
    test = json.load(f)

cipher_hex = test['ciphertext_hex']
plaintext = test['plaintext']

print(f"原文：{plaintext}")
print(f"原文长度：{len(plaintext)} 字节")

# Java 密文格式：C1C3C2 (C1=65 字节，C3=32 字节，C2=变长)
c1 = cipher_hex[0:130]
c3 = cipher_hex[130:194]
c2 = cipher_hex[194:]

print(f"\nJava 密文 (C1C3C2):")
print(f"  C1: {c1}")
print(f"  C3: {c3}")
print(f"  C2: {c2}")

# 重新排列为 C1C2C3 格式 (gmssl 期望的格式)
rearranged_hex = c1 + c2 + c3
rearranged_bytes = bytes.fromhex(rearranged_hex)

print(f"\n重新排列后 (C1C2C3):")
print(f"  {rearranged_hex}")

# 使用 gmssl 解密
crypt = sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, mode=1)

try:
    decrypted = crypt.decrypt(rearranged_bytes)
    print(f"\n解密结果：{decrypted}")
    print(f"解密结果 (utf-8): {decrypted.decode('utf-8')}")
    print(f"匹配原文：{decrypted.decode('utf-8') == plaintext}")
except Exception as e:
    print(f"\n解密失败：{e}")