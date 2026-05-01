#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试密文格式：对比 Java 和 gmssl 的密文结构
"""

import json
from pathlib import Path

# 加载 Java 测试用例
test_file = Path('testcase/results/java_encrypt/test_1_simple_text.json')
with open(test_file, 'r', encoding='utf-8') as f:
    test = json.load(f)

cipher_hex = test['ciphertext_hex']
plaintext = test['plaintext']

print(f"明文：{plaintext}")
print(f"明文长度：{len(plaintext)} 字符")
print(f"密文 (HEX): {cipher_hex}")
print(f"密文长度：{len(cipher_hex)//2} 字节")

# Java 密文格式：C1C3C2
# C1 = 65 字节 (130 HEX)
# C3 = 32 字节 (64 HEX)
# C2 = 变长

c1 = cipher_hex[0:130]
c3 = cipher_hex[130:194]
c2 = cipher_hex[194:]

print(f"\n=== Java 密文格式 (C1C3C2) ===")
print(f"C1 (65 字节): {c1}")
print(f"C3 (32 字节): {c3}")
print(f"C2 ({len(c2)//2}字节): {c2}")

# gmssl 密文格式：C1C2C3
# C1 = 65 字节
# C2 = 变长
# C3 = 32 字节

print(f"\n=== 尝试 C1C2C3 格式 ===")
c1_gm = cipher_hex[0:130]
# 假设 C2 长度与明文相同
plaintext_len = len(plaintext)
c2_gm = cipher_hex[130:130+plaintext_len*2]
c3_gm = cipher_hex[130+plaintext_len*2:]

print(f"C1 (65 字节): {c1_gm}")
print(f"C2 ({plaintext_len}字节): {c2_gm}")
print(f"C3 (剩余): {c3_gm}")
print(f"C3 长度：{len(c3_gm)//2} 字节")

# 尝试重新排列密文
print(f"\n=== 重新排列为 C1C2C3 ===")
rearranged = c1 + c2 + c3
print(f"重新排列后：{rearranged}")
print(f"长度：{len(rearranged)//2} 字节")