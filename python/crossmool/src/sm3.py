#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM3 国密哈希算法实现 - 与 Java BouncyCastle 完全兼容
"""

from gmssl import sm3

def sm3_hash(data: bytes) -> bytes:
    """
    计算 SM3 哈希值
    :param data: 待哈希的字节数据
    :return: 32 字节的哈希值
    """
    return sm3.sm3_hash(list(data))

def sm3_hash_hex(data: bytes) -> str:
    """
    计算 SM3 哈希值 (Hex 格式)
    :param data: 待哈希的字节数据
    :return: Hex 格式的哈希值 (64 字符)
    """
    return sm3.sm3_hash(list(data))

def sm3_kdf(z: str, length: int) -> str:
    """
    SM3 密钥派生函数
    :param z: HEX 字符串格式的输入
    :param length: 派生密钥长度 (字节)
    :return: HEX 格式的派生密钥
    """
    return sm3.sm3_kdf(z, length)

# 便捷函数
hash = sm3_hash
hash_hex = sm3_hash_hex
kdf = sm3_kdf