#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度分析 Java 签名 vs C 验签不匹配原因
修正 gmssl-python verify API
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
ct_binary = bytes.fromhex(CT_HEX)
print(f"内容 (CT_HEX UTF-8): {len(content_utf8)} 字节")

print("\n" + "=" * 60)
print("逐一测试各种验签方案（data 参数传 bytes）")
print("=" * 60)

cases = [
    ("方案1: SM3(Z || CT_HEX.encode('utf-8'))", Z + content_utf8),
    ("方案2: SM3(Z || CT_binary)", Z + ct_binary),
    ("方案3: SM3(CT_HEX.encode('utf-8'))", content_utf8),
    ("方案4: SM3(CT_binary)", ct_binary),
]

for name, data in cases:
    dgst = sm3_hash_bytes(data)  # bytes
    result = sm2_obj.verify(sig_raw_hex, dgst)  # 传 bytes，不是 hex 字符串！
    print(f"\n{name}")
    print(f"  哈希: {dgst.hex()}")
    print(f"  验签: {'✅ 成功' if result else '❌ 失败'}")

# 验证 Z 值
print(f"\n\nZ 值计算:")
print(f"  Python 计算: {Z.hex()}")
print(f"  C 端输出:    fb23ae08d4d3c8d76b9ee3a0f7741547d2d4888f2e0f9f2fb56a9f0a24910fb40")
# 注意：上次调试时C端Z值有些字符可能不准确，让我检查
# C 端在 debug_verify_deep.py 中输出了 Z 值

# 用 gmssl-python 内置 verify_with_sm3（先看它接收什么）
print("\n" + "=" * 60)
print("用 gmssl-python verify_with_sm3")
print("=（内部会计算 SM3(Z || data)）")
print("=" * 60)
# verify_with_sm3(sign, data) where sign=hex_r_s, data=bytes
try:
    result_vws = sm2_obj.verify_with_sm3(sig_raw_hex, content_utf8)
    print(f"verify_with_sm3(sig, CT_HEX_utf8_bytes): {'✅ 成功' if result_vws else '❌ 失败'}")
except Exception as e:
    print(f"verify_with_sm3 异常: {e}")

try:
    result_vws2 = sm2_obj.verify_with_sm3(sig_raw_hex, ct_binary)
    print(f"verify_with_sm3(sig, CT_binary): {'✅ 成功' if result_vws2 else '❌ 失败'}")
except Exception as e:
    print(f"verify_with_sm3 异常: {e}")

# 逐步跟踪 gmssl-python verify_with_sm3 对 content_utf8 的计算
print("\n" + "=" * 60)
print("手动复现 gmssl-python _sm3_z(content_utf8) 的哈希")
print("=" * 60)
import inspect
src_z = inspect.getsource(sm2_obj._sm3_z)
print(src_z)

# _sm3_z 实现中：
# z = '0080' + '31...' (USER_ID_HEX) + a + b + g + public_key
# Za = sm3(unhex(z))  -- Za 是一个 hex 字符串
# M_ = (Za + data.hex()).encode('utf-8')  -- data.hex() 把 bytes 变成 hex 字符串，再 utf8 编码
# e = sm3(unhex(M_))
# 这意味着: 实际计算的是 SM3(Za_bytes || data_bytes)
# 即: SM3(Z || content_bytes)
# 但 Za 是 hex 字符串后 unhexlify... 

print("\n手动模拟:")
# Za (SM3 of Z input material)
z_str = '0080' + USER_ID.hex() + \
    'fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc' + \
    '28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93' + \
    '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7' + \
    'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0' + \
    x_hex + y_hex
Za_hex = gmssl_sm3.sm3_hash(list(binascii.a2b_hex(z_str)))  # 返回 hex 字符串
print(f"Za (hex str): {Za_hex}")
print(f"标准 Z:       {Z.hex()}")
print(f"Za == Z: {Za_hex.lower() == Z.hex().lower()}")

# 现在 _sm3_z 实际计算的 M_
# data = content_utf8
# M_ = (Za + data.hex()).encode('utf-8')
# = (Za_hex + content_utf8.hex()).encode('utf-8')
M_hex_str = Za_hex + content_utf8.hex()
print(f"\nM_ = Za_hex + content_utf8.hex()")
print(f"M_ 长度: {len(M_hex_str)} 字符 = {len(M_hex_str)//2} 字节")
e_hex = gmssl_sm3.sm3_hash(list(binascii.a2b_hex(M_hex_str)))  # sm3 of unhex(M_)
print(f"最终 e (sm3_z result): {e_hex}")
# 这相当于 SM3(Z_bytes || content_utf8_bytes)
e_correct = sm3_hash_bytes(Z + content_utf8)
print(f"标准 SM3(Z||content):  {e_correct.hex()}")
print(f"一致: {e_hex.lower() == e_correct.hex().lower()}")
print(f"\n=> gmssl-python _sm3_z 实际上计算的是 SM3(Z || content_bytes)，这是正确的！")
