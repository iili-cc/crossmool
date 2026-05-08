#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度分析 Java 签名 vs C 验签不匹配原因
修正 gmssl-python API 使用方式
"""
from gmssl import sm2 as gmssl_sm2, sm3 as gmssl_sm3
import binascii

def sm3_hash_bytes(data: bytes) -> bytes:
    """使用 gmssl sm3 对字节进行哈希，返回 bytes"""
    result_hex = gmssl_sm3.sm3_hash(list(data))  # 返回 hex 字符串
    return bytes.fromhex(result_hex)

# ---- 测试数据 ----
CT_HEX = "04e4534be6847921acdf2f0ff2e4d1e0057bcdba9450c64af197c30762e8356531a26295dfbfc6335d21ad8176312e8c9b0489400599657c6eacf197f08db43a35d96c52a989a8aab3f9b855a56bb507e5ebe81f2aea88d76d72671a3bd1244273f80dd60d50556bb4e5cff5fc6a02b97fdf"
SIG_HEX = "3046022100cae388164ba6e735814a03e7cff2a09fa017db831a2ad932b9c2a226776fe07f022100dde7ae2b5c0a32ff04c89d5ebe85911d5015d2593eb012ca66caa5d5ef4e6686"
SIGN_PUBKEY_HEX = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

def extract_raw_pubkey(x509_hex):
    b = bytes.fromhex(x509_hex)
    idx = b.find(b'\x04')
    raw = b[idx:]
    assert len(raw) == 65
    return raw

def parse_der_sig(der_hex):
    data = bytes.fromhex(der_hex)
    assert data[0] == 0x30
    idx = 1
    b = data[idx]
    if b & 0x80:
        nb = b & 0x7f; idx += 1 + nb
    else:
        idx += 1
    assert data[idx] == 0x02; idx += 1
    r_len = data[idx]; idx += 1
    r_bytes = data[idx:idx+r_len]; idx += r_len
    assert data[idx] == 0x02; idx += 1
    s_len = data[idx]; idx += 1
    s_bytes = data[idx:idx+s_len]
    r_int = int.from_bytes(r_bytes, 'big')
    s_int = int.from_bytes(s_bytes, 'big')
    return r_int.to_bytes(32, 'big'), s_int.to_bytes(32, 'big')

raw_pub = extract_raw_pubkey(SIGN_PUBKEY_HEX)
px_bytes = raw_pub[1:33]
py_bytes = raw_pub[33:65]
x_hex = px_bytes.hex()
y_hex = py_bytes.hex()

r32, s32 = parse_der_sig(SIG_HEX)
sig_raw_hex = (r32 + s32).hex()

print(f"公钥 x: {x_hex}")
print(f"公钥 y: {y_hex}")
print(f"签名 r: {r32.hex()}")
print(f"签名 s: {s32.hex()}")

sm2_obj = gmssl_sm2.CryptSM2(public_key=x_hex+y_hex, private_key="")

# SM2 曲线参数（小写，与 gmssl-python 一致）
USER_ID = b"1234567812345678"
ENTL = (len(USER_ID) * 8).to_bytes(2, 'big')
a_bytes = bytes.fromhex("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc")
b_bytes = bytes.fromhex("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93")
Gx_bytes = bytes.fromhex("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7")
Gy_bytes = bytes.fromhex("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")

# 计算标准 Z 值
z_raw = ENTL + USER_ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + px_bytes + py_bytes
Z = sm3_hash_bytes(z_raw)
print(f"\n标准 Z 值: {Z.hex()}")

content_utf8 = CT_HEX.encode('utf-8')
print(f"内容 (CT_HEX UTF-8): {len(content_utf8)} 字节")

print("\n" + "=" * 60)
print("逐一测试各种验签方案")
print("=" * 60)

cases = [
    ("方案1: SM3(Z || CT_HEX.encode('utf-8'))", Z + content_utf8),
    ("方案2: SM3(Z || CT_binary)", Z + bytes.fromhex(CT_HEX)),
    ("方案3: SM3(CT_HEX.encode('utf-8'))", content_utf8),
    ("方案4: SM3(CT_binary)", bytes.fromhex(CT_HEX)),
]

for name, data in cases:
    dgst = sm3_hash_bytes(data)
    result = sm2_obj.verify(sig_raw_hex, dgst.hex())
    print(f"\n{name}")
    print(f"  哈希: {dgst.hex()}")
    print(f"  验签: {'✅ 成功' if result else '❌ 失败'}")

# 测试其他用例
print("\n" + "=" * 60)
print("用其他测试用例（test_2/3/4）验证")
print("=" * 60)

import json, os
test_dir = os.path.dirname(os.path.abspath(__file__))
result_dir = os.path.join(test_dir, "results", "java_encrypt")
keys_file = os.path.join(test_dir, "keys", "java", "keys.json")

with open(keys_file) as f:
    keys = json.load(f)
sign_pub_hex = keys["signature_public_key"]["hex"]

for fname in sorted(os.listdir(result_dir)):
    if not fname.startswith("test_") or not fname.endswith(".json"):
        continue
    fpath = os.path.join(result_dir, fname)
    with open(fpath) as f:
        data = json.load(f)
    
    ct = data["ciphertext_hex"]
    sig = data["signature_hex"]
    tid = data["test_case_id"]
    tname = data["test_case_name"]
    
    # 提取该测试用例的公钥
    raw = extract_raw_pubkey(sign_pub_hex)
    px2 = raw[1:33]
    py2 = raw[33:65]
    
    z2_raw = ENTL + USER_ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + px2 + py2
    Z2 = sm3_hash_bytes(z2_raw)
    
    content2 = ct.encode('utf-8')
    dgst2 = sm3_hash_bytes(Z2 + content2)
    
    r2, s2 = parse_der_sig(sig)
    sig2_hex = (r2 + s2).hex()
    
    sm2_2 = gmssl_sm2.CryptSM2(public_key=px2.hex()+py2.hex(), private_key="")
    result2 = sm2_2.verify(sig2_hex, dgst2.hex())
    print(f"[{tid}] {tname}: {'✅' if result2 else '❌'}")

# 检查 gmssl-python verify 的实现
print("\n" + "=" * 60)
print("gmssl-python verify() 的实现")
print("=" * 60)
import inspect
src = inspect.getsource(sm2_obj.verify)
print(src)
