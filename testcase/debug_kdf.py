#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试 KDF 函数
"""

from gmssl import sm3

# 测试数据
s_x = "6df309772cc2564d1dd07c4b9138c7088ee89045a70902ec23a4b4a1519f5162"
s_y = "cf25424c85efb39584aa283cb7e22d9613ff93918c39cc5487fc7e7c21a21a"
mlen = 17

# 测试不同的 KDF 输入格式
print("测试 1: KDF(x||y, mlen)")
t1 = sm3.sm3_kdf((s_x + s_y).encode('utf8'), mlen)
print(f"  结果：{t1}")

print("\n测试 2: KDF(bytes(x||y), mlen)")
xy_bytes = bytes.fromhex(s_x + s_y)
t2 = sm3.sm3_kdf(xy_bytes, mlen)
print(f"  结果：{t2}")

print("\n测试 3: KDF(x||M||y, mlen) 其中 M='Hello, Crossmool!'")
M = "Hello, Crossmool!"
M_hex = M.encode('utf-8').hex()
xmy_bytes = bytes.fromhex(s_x + M_hex + s_y)
t3 = sm3.sm3_kdf(xmy_bytes, mlen)
print(f"  结果：{t3}")

# 验证 C3
c3_expected = "d96c52a989a8aab3f9b855a56bb507e5ebe81f2aea88d76d72671a3bd1244273"
c3_calc = sm3.sm3_hash([i for i in xmy_bytes])
print(f"\nC3 计算：{c3_calc}")
print(f"C3 期望：{c3_expected}")
print(f"匹配：{c3_calc == c3_expected}")