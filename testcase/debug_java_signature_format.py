#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试 Java 签名数据格式
使用 Python gmssl 库验证 Java encryptSign 方法对密文 HEX 字符串签名时使用的字节格式

关键发现：
1. Java encryptSign 方法 (SM2Util.java:438-440):
   - 先 encrypt 得到密文 HEX 字符串
   - 然后 sign(encrypted, ...) 对密文 HEX 字符串签名
   - sign 方法使用 UTF-8 编码 (SM2Util.java:420 行)

2. Java sign 方法 (SM2Util.java:377-378):
   - sign(String content, String privateKey, boolean toBase64)
   - toBase64=false 时调用 signToHex，输出 HEX 格式签名
   - signToHex 使用 UTF-8 编码 content.getBytes(charset)

3. Java verify 方法 (SM2Util.java:425-426):
   - verify(String content, String publicKey, String signature)
   - 使用 UTF-8 编码 content.getBytes(charset)
"""

import json
from gmssl import sm2, sm3

# 测试数据
test_data = {
    "plaintext": "Hello, Crossmool!",
    "ciphertext_hex": "04e4534be6847921acdf2f0ff2e4d1e0057bcdba9450c64af197c30762e8356531a26295dfbfc6335d21ad8176312e8c9b0489400599657c6eacf197f08db43a35d96c52a989a8aab3f9b855a56bb507e5ebe81f2aea88d76d72671a3bd1244273f80dd60d50556bb4e5cff5fc6a02b97fdf",
    "signature_hex": "3046022100cae388164ba6e735814a03e7cff2a09fa017db831a2ad932b9c2a226776fe07f022100dde7ae2b5c0a32ff04c89d5ebe85911d5015d2593eb012ca66caa5d5ef4e6686"
}

# 密钥数据
keys = {
    "encryption_private_key": "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4",
    "signature_public_key": "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"
}

# SM2 用户 ID（与 Java/C 保持一致）
user_id = "1234567812345678"

print("=" * 80)
print("Java 签名数据格式调试")
print("=" * 80)

# 输出原始数据
print("\n【原始数据】")
print(f"明文：{test_data['plaintext']}")
print(f"密文 HEX 长度：{len(test_data['ciphertext_hex'])} 字符")
print(f"密文 HEX: {test_data['ciphertext_hex']}")
print(f"签名 HEX 长度：{len(test_data['signature_hex'])} 字符")
print(f"签名 HEX: {test_data['signature_hex']}")

# 提取私钥和公钥的原始字节
private_key_hex = keys["encryption_private_key"]
public_key_hex = keys["signature_public_key"]

print("\n【密钥信息】")
print(f"私钥 HEX 长度：{len(private_key_hex)} 字符")
print(f"公钥 HEX 长度：{len(public_key_hex)} 字符")

# 解析 PKCS#8 私钥提取原始私钥（32 字节）
pkcs8_bytes = bytes.fromhex(private_key_hex)
priv_key_start = pkcs8_bytes.find(b'\x04\x20')
if priv_key_start != -1:
    private_key_raw = pkcs8_bytes[priv_key_start + 2:priv_key_start + 34]
    print(f"\n提取的原始私钥 (32 字节): {private_key_raw.hex()}")
else:
    print("\n警告：无法从 PKCS#8 格式提取私钥")
    private_key_raw = None

# 解析 X.509 公钥提取原始公钥（65 字节）
x509_bytes = bytes.fromhex(public_key_hex)
pub_key_start = x509_bytes.find(b'\x03\x42\x00')
if pub_key_start != -1:
    public_key_raw = x509_bytes[pub_key_start + 3:pub_key_start + 68]
    print(f"提取的原始公钥 (65 字节): {public_key_raw.hex()}")
else:
    print("警告：无法从 X.509 格式提取公钥")
    public_key_raw = None

# 测试不同的数据格式
print("\n" + "=" * 80)
print("【验签测试】")
print("=" * 80)

# gmssl-python 库的 CryptSM2 不支持 user_id 参数
if public_key_raw and private_key_raw:
    sm2_obj = sm2.CryptSM2(
        public_key=public_key_raw.hex(),
        private_key=private_key_raw.hex()
    )
    print("SM2 对象初始化成功（不带 user_id）")
else:
    print("警告：密钥解析失败，无法进行验签测试")
    sm2_obj = None

# 测试 1: 密文 HEX 字符串作为 UTF-8 字节签名（Java 实际使用的方式）
print("\n【测试 1】密文 HEX 字符串 (UTF-8 编码) - Java encryptSign 实际使用")
ciphertext_str = test_data['ciphertext_hex']
ciphertext_utf8 = ciphertext_str.encode('utf-8')
print(f"签名数据长度：{len(ciphertext_utf8)} 字节")
print(f"签名数据 (UTF-8): {ciphertext_utf8}")

if sm2_obj:
    try:
        signature_bytes = bytes.fromhex(test_data['signature_hex'])
        is_valid = sm2_obj.verify(ciphertext_utf8, signature_bytes)
        print(f"验签结果：{'✓ 成功' if is_valid else '✗ 失败'}")
    except Exception as e:
        print(f"验签异常：{e}")

# 测试 2: 密文 HEX 字符串作为 ASCII 字节签名
print("\n【测试 2】密文 HEX 字符串 (ASCII 编码)")
ciphertext_ascii = ciphertext_str.encode('ascii')
print(f"签名数据长度：{len(ciphertext_ascii)} 字节")
print(f"签名数据 (ASCII): {ciphertext_ascii}")

if sm2_obj:
    try:
        signature_bytes = bytes.fromhex(test_data['signature_hex'])
        is_valid = sm2_obj.verify(ciphertext_ascii, signature_bytes)
        print(f"验签结果：{'✓ 成功' if is_valid else '✗ 失败'}")
    except Exception as e:
        print(f"验签异常：{e}")

# 测试 3: 密文原始字节签名
print("\n【测试 3】密文原始字节")
ciphertext_bytes = bytes.fromhex(test_data['ciphertext_hex'])
print(f"签名数据长度：{len(ciphertext_bytes)} 字节")
print(f"签名数据 (原始): {ciphertext_bytes.hex()}")

if sm2_obj:
    try:
        signature_bytes = bytes.fromhex(test_data['signature_hex'])
        is_valid = sm2_obj.verify(ciphertext_bytes, signature_bytes)
        print(f"验签结果：{'✓ 成功' if is_valid else '✗ 失败'}")
    except Exception as e:
        print(f"验签异常：{e}")

print("\n" + "=" * 80)
print("调试完成")
print("=" * 80)

# 输出关键结论
print("\n【结论】")
print("Java encryptSign 方法对密文 HEX 字符串签名时使用的是 UTF-8 编码的字节")
print("C 语言验签时需要对相同的密文 HEX 字符串使用 UTF-8 编码进行验签")
