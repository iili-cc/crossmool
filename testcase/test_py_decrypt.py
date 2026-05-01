#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试 Python 解密 Java 密文"""

from gmssl import sm2

# Java 密钥（原始格式）
priv_raw = 'f245ec046b24057e6b96939ac67b7a9fe3716b3c5097c844f34e87c9d32f840f'
pub_raw = '044624fc108ffe912034f1a95a1bffa9abf19f351d72ce8e211ed66d3d25a916dee35bc8103e6f91f366652fcf7c298c84a8da65edc28bd6535e8351c8f6460ee5'

# Java 密文
ct = '04c56b6c575c79467fc8e13a837f0d4be2366f6496755c4ed39d25a8772102263b8b2fa05ffd59132a0b2318a2775f22dfba8d715848454d3059fcc277fe992938b150101253eb19e2726e78ea0bb27469f75be1ff3357f2524e33de52866f4d8ed919abae779bbcb0125ce189124bd295da'

print('私钥:', priv_raw)
print('公钥:', pub_raw)
print('密文:', ct[:60] + '...')

# 尝试解密 - mode=1 是 C1C3C2
sm2_crypt = sm2.CryptSM2(public_key=pub_raw, private_key=priv_raw, mode=1)
try:
    decrypted = sm2_crypt.decrypt(ct)
    print('解密成功:', decrypted)
except Exception as e:
    print('解密失败:', e)