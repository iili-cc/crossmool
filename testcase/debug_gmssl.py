#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试 gmssl 库的底层实现
"""

from gmssl import sm2, sm3

# 测试 gmssl 的解密方法
priv_hex = "72e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057"
pub_hex = "048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

# 创建 CryptSM2 对象
crypt = sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, mode=1)

# 查看对象属性
print("CryptSM2 对象属性:")
for attr in dir(crypt):
    if not attr.startswith('__'):
        print(f"  {attr}")

# 测试解密
cipher_hex = "04e4534be6847921acdf2f0ff2e4d1e0057bcdba9450c64af197c30762e8356531a26295dfbfc6335d21ad8176312e8c9b0489400599657c6eacf197f08db43a35d96c52a989a8aab3f9b855a56bb507e5ebe81f2aea88d76d72671a3bd1244273f80dd60d50556bb4e5cff5fc6a02b97fdf"
cipher_bytes = bytes.fromhex(cipher_hex)

print(f"\n密文长度：{len(cipher_bytes)} 字节")

# 尝试解密
try:
    decrypted = crypt.decrypt(cipher_bytes)
    print(f"解密结果：{decrypted}")
    print(f"解密结果 (hex): {decrypted.hex()}")
except Exception as e:
    print(f"解密失败：{e}")

# 测试加密
test_msg = b"Hello, Crossmool!"
try:
    encrypted = crypt.encrypt(test_msg)
    print(f"\n加密结果：{encrypted.hex()}")
    print(f"加密长度：{len(encrypted)} 字节")
    
    # 再解密
    decrypted2 = crypt.decrypt(encrypted)
    print(f"解密结果：{decrypted2}")
    print(f"匹配：{decrypted2 == test_msg}")
except Exception as e:
    print(f"加密失败：{e}")