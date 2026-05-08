#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度分析 Java 签名 vs C 验签不匹配原因
"""
from gmssl import sm2 as gmssl_sm2, sm3 as gmssl_sm3
import binascii

def sm3_hash_bytes(data: bytes) -> bytes:
    """使用 gmssl sm3 对字节进行哈希，返回 bytes"""
    return bytes(gmssl_sm3.sm3_hash(list(data)))

# ---- 测试数据 ----
CT_HEX = "04e4534be6847921acdf2f0ff2e4d1e0057bcdba9450c64af197c30762e8356531a26295dfbfc6335d21ad8176312e8c9b0489400599657c6eacf197f08db43a35d96c52a989a8aab3f9b855a56bb507e5ebe81f2aea88d76d72671a3bd1244273f80dd60d50556bb4e5cff5fc6a02b97fdf"
SIG_HEX = "3046022100cae388164ba6e735814a03e7cff2a09fa017db831a2ad932b9c2a226776fe07f022100dde7ae2b5c0a32ff04c89d5ebe85911d5015d2593eb012ca66caa5d5ef4e6686"
SIGN_PUBKEY_HEX = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

def extract_raw_pubkey(x509_hex):
    b = bytes.fromhex(x509_hex)
    idx = b.find(b'\x04')
    raw = b[idx:]
    assert len(raw) == 65, f"公钥长度异常: {len(raw)}"
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
print(f"r: {r32.hex()}")
print(f"s: {s32.hex()}")

sm2_obj = gmssl_sm2.CryptSM2(public_key=x_hex+y_hex, private_key="")

# SM2 曲线参数
USER_ID = b"1234567812345678"
ENTL = (len(USER_ID) * 8).to_bytes(2, 'big')  # 0x0080 = 128
a_bytes = bytes.fromhex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
b_bytes = bytes.fromhex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")
Gx_bytes = bytes.fromhex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
Gy_bytes = bytes.fromhex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")

# 计算标准 Z 值
z_raw = ENTL + USER_ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + px_bytes + py_bytes
Z = sm3_hash_bytes(z_raw)
print(f"\n标准 Z 值: {Z.hex()}")

# 签名内容
content_str = CT_HEX
content_utf8 = content_str.encode('utf-8')
print(f"内容 (UTF-8 bytes): {content_utf8[:20].hex()}... ({len(content_utf8)}字节)")

print("\n" + "=" * 60)
print("逐一测试各种验签方案")
print("=" * 60)

cases = [
    ("方案1: SM3(Z || CT_HEX.encode('utf-8'))", Z + content_utf8),
    ("方案2: SM3(Z || CT_HEX_binary)", Z + bytes.fromhex(CT_HEX)),
    ("方案3: 仅 SM3(CT_HEX.encode('utf-8'))", content_utf8),
    ("方案4: 仅 SM3(CT_HEX_binary)", bytes.fromhex(CT_HEX)),
]

for name, data in cases:
    dgst = sm3_hash_bytes(data)
    result = sm2_obj.verify(sig_raw_hex, dgst.hex())
    print(f"{name}")
    print(f"  哈希: {dgst.hex()}")
    print(f"  验签: {'✅ 成功' if result else '❌ 失败'}")

# 检查 gmssl-python 的 ecc_table 用的曲线参数
print("\n" + "=" * 60)
print("检查 gmssl-python ecc_table 曲线参数")
print("=" * 60)
tbl = sm2_obj.ecc_table
print(f"a: {tbl.get('a', '')}")
print(f"b: {tbl.get('b', '')}")
g = tbl.get('g', '')
print(f"g (Gx+Gy): {g[:32]}...")
print(f"  Gx 期望: 32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7")
print(f"  Gy 期望: bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")
a_match = tbl.get('a', '').lower() == "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc"
g_match = g.lower() == "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"
print(f"  a 一致: {a_match}")
print(f"  g 一致: {g_match}")

# 用 gmssl-python 内置 _sm3_z（接受 bytes）
print("\n" + "=" * 60)
print("用 gmssl-python 内置 verify_with_sm3 手动追踪")
print("=" * 60)
# _sm3_z(data) 实现：data 是什么类型?
# 查看 Java SM2Signer 传入的内容 vs C 验签传入的内容
# Java: sm2Signer.update(content, 0, content.length) 其中 content = CT_HEX.getBytes(UTF-8)
# 但是 _sm3_z 接收 data 参数，如果 data 是 bytes：
#   M_ = (Za + data.hex()).encode('utf-8')  <-- data.hex() 把228字节变成456字符的HEX字符串
#   这等价于 SM3(Z || CT_HEX_BYTES_AS_HEX_STRING)

# 如果 data 是字符串（CT_HEX字符串）：
#   M_ = (Za + "04e4...fdf").encode('utf-8')
#   这等价于 SM3(Z || CT_HEX_STRING_LITERAL)

# Java 签名时 content = CT_HEX.getBytes("UTF-8") = 228字节
# Java SM2Signer 内部: Z_hash || message_bytes，然后做 SM3
# 所以 Java 哈希 = SM3(Z || CT_HEX.getBytes("UTF-8"))
# = SM3(Z || content_utf8) = 方案1

# 但方案1返回了 False！说明 Python 的 verify 函数有问题，或者
# gmssl-python 的 SM2 数学与 BouncyCastle 不完全兼容

# 让我检查 gmssl-python verify 函数的实现
import inspect
src = inspect.getsource(sm2_obj.verify)
print(src[:500])
