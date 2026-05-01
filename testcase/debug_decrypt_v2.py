#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复 SM2 解密：使用正确的 KDF 输入格式
SM2 解密步骤：
1. 从 C1 和私钥计算 S = d * C1
2. 计算 t = KDF(x2 || M || y2, mlen)  -- 注意这里需要 M
3. 但 M 未知，所以先计算 t' = KDF(x2 || y2, mlen) 来解密 C2 得到 M
4. 然后用 M 重新计算 t = KDF(x2 || M || y2, mlen) 验证 C3
"""

import json
from pathlib import Path
from gmssl import sm2, sm3

# 加载密钥
priv_hex = "72e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057"
pub_hex = "048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

# 加载测试用例
test_file = Path(__file__).parent / 'results' / 'java_encrypt' / 'test_1_simple_text.json'
with open(test_file, 'r', encoding='utf-8') as f:
    test = json.load(f)

cipher_hex = test['ciphertext_hex']
plaintext = test['plaintext']

print(f"原文：{plaintext}")
print(f"密文：{cipher_hex}")

# Java BouncyCastle 使用 C1C3C2 格式
c1_hex = cipher_hex[0:130]
c3_hex = cipher_hex[130:194]
c2_hex = cipher_hex[194:]

print(f"\nC1: {c1_hex}")
print(f"C3: {c3_hex}")
print(f"C2: {c2_hex}")

# 使用 gmssl 计算 S = d * C1
crypt = sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, mode=1)

# C1 格式：04 || x || y
S_hex = crypt._kg(int(priv_hex, 16), c1_hex)
print(f"\nS = d * C1: {S_hex}")

# S 格式：04 || x2 || y2
s_x = S_hex[2:66]
s_y = S_hex[66:130]

print(f"s_x: {s_x}")
print(f"s_y: {s_y}")

# 计算 t = KDF(x2 || y2, mlen) 用于解密
# gmssl 的 sm3_kdf 期望 HEX 字符串输入
mlen = len(c2_hex) // 2
xy_hex = s_x + s_y
t = sm3.sm3_kdf(xy_hex, mlen)
print(f"\nt (KDF x||y): {t}")

# 解密 M = C2 XOR t
M_hex = format(int(c2_hex, 16) ^ int(t, 16), '0%dx' % (mlen * 2))
M_bytes = bytes.fromhex(M_hex)
print(f"M (解密后): {M_bytes}")

# 验证 C3 = SM3(x2 || M || y2)
C3_calc = sm3.sm3_hash([i for i in bytes.fromhex(s_x + M_hex + s_y)])
print(f"\nC3 计算值：{C3_calc}")
print(f"C3 原始值：{c3_hex}")
print(f"C3 匹配：{C3_calc == c3_hex}")

# 尝试解码
try:
    M_str = M_bytes.decode('utf-8')
    print(f"M (UTF-8): {M_str}")
    print(f"与原文匹配：{M_str == plaintext}")
except:
    print("无法解码为 UTF-8")