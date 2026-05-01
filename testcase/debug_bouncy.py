#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
使用 pycryptodome 的 SM2 实现（如果可用）
或者手动实现 SM2 解密
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
# C1 = 65 字节 (椭圆曲线点)
# C3 = 32 字节 (SM3 哈希)
# C2 = 变长 (密文)

c1_hex = cipher_hex[0:130]
c3_hex = cipher_hex[130:194]
c2_hex = cipher_hex[194:]

print(f"\nC1: {c1_hex}")
print(f"C3: {c3_hex}")
print(f"C2: {c2_hex}")

# 手动实现 SM2 解密（C1C3C2 格式）
# 1. 从 C1 和私钥计算共享密钥 S = d * C1
crypt = sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, mode=1)

# C1 是椭圆曲线点，需要转换为坐标
C1_bytes = bytes.fromhex(c1_hex)
print(f"\nC1 bytes: {C1_bytes.hex()}")

# 使用 gmssl 的 _kg 函数计算 S = d * C1
# 但 _kg 需要 k (整数) 和 P (点) 作为参数
# 这里我们需要计算 S = priv * C1

# 尝试使用 gmssl 的内部方法
try:
    # 从 C1 计算共享密钥
    # C1 格式：04 || x || y (各 32 字节)
    c1_x = c1_hex[2:66]
    c1_y = c1_hex[66:130]
    
    # 计算 S = d * C1
    # 使用 gmssl 的 _kg 方法
    S_hex = crypt._kg(int(priv_hex, 16), c1_hex)
    print(f"S = d * C1: {S_hex}")
    
    # S 格式：04 || x || y
    s_x = S_hex[2:66]
    s_y = S_hex[66:130]
    
    # 2. 计算 t = KDF(x || M || y, mlen)
    # 但 M 未知，需要先解密 C2
    # 使用 t = KDF(x || y, mlen)
    mlen = len(c2_hex) // 2
    t = sm3.sm3_kdf((s_x + s_y).encode('utf8'), mlen)
    print(f"t (KDF): {t}")
    
    # 3. M = C2 XOR t
    M_hex = format(int(c2_hex, 16) ^ int(t, 16), '0%dx' % (mlen * 2))
    M_bytes = bytes.fromhex(M_hex)
    print(f"M (解密后): {M_bytes}")
    
    # 4. 验证 C3
    C3_calc = sm3.sm3_hash([i for i in bytes.fromhex(s_x + M_hex + s_y)])
    print(f"C3 计算值：{C3_calc}")
    print(f"C3 原始值：{c3_hex}")
    print(f"C3 匹配：{C3_calc == c3_hex}")
    
except Exception as e:
    print(f"解密失败：{e}")
    import traceback
    traceback.print_exc()