#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度分析 Java 签名 vs C 验签不匹配的原因
"""
from gmssl import sm2 as gmssl_sm2, sm3 as gmssl_sm3
import binascii

def sm3_hash_bytes(data: bytes) -> bytes:
    """使用 gmssl sm3 对字节进行哈希"""
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

# SM2 曲线参数
USER_ID = b"1234567812345678"
ENTL = (len(USER_ID) * 8).to_bytes(2, 'big')  # 0x0080
a_bytes = bytes.fromhex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
b_bytes = bytes.fromhex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")
Gx_bytes = bytes.fromhex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
Gy_bytes = bytes.fromhex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")

sm2_obj = gmssl_sm2.CryptSM2(public_key=x_hex+y_hex, private_key="")

print("=" * 60)
print("计算标准 Z 值")
print("=" * 60)
z_input = ENTL + USER_ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + px_bytes + py_bytes
Z = sm3_hash_bytes(z_input)
print(f"ENTL: {ENTL.hex()}")
print(f"USER_ID: {USER_ID.hex()}")
print(f"Z = {Z.hex()}")

# 签名内容
content_bytes = CT_HEX.encode('utf-8')  # 228字节 ASCII
print(f"\n签名内容: '{CT_HEX[:30]}...' ({len(content_bytes)} bytes UTF-8)")

print("\n" + "=" * 60)
print("方案1: 标准 SM2WithSM3 - SM3(Z || content_bytes)")
print("=" * 60)
dgst1 = sm3_hash_bytes(Z + content_bytes)
print(f"哈希: {dgst1.hex()}")
r1 = sm2_obj.verify(sig_raw_hex, dgst1.hex())
print(f"验签: {r1}")

print("\n" + "=" * 60)
print("方案2: 检查 gmssl-python _sm3_z 的实际计算")
print("=" * 60)
# gmssl-python 的 _sm3_z:
# z = '0080'+'31323334353637383132333435363738' + ecc_table stuff + public_key
# Za = sm3(unhex(z))  这里 z 是全大写还是小写?
z_str = '0080' + USER_ID.hex() + \
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC' + \
    '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93' + \
    '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7' + \
    'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0' + \
    x_hex + y_hex
Za2 = sm3_hash_bytes(binascii.a2b_hex(z_str))
print(f"gmssl-python Za (全大写参数): {Za2.hex()}")
print(f"标准 Z:                       {Z.hex()}")
print(f"一致: {Za2 == Z}")

# 看 ecc_table
print("\ngmssl-python ecc_table 的曲线参数:")
print(f"a: {sm2_obj.ecc_table.get('a', 'N/A')}")
print(f"b: {sm2_obj.ecc_table.get('b', 'N/A')}")
g_str = sm2_obj.ecc_table.get('g', 'N/A')
print(f"g: {g_str}")
# g 是 Gx || Gy
Gxy_actual = g_str.lower()
print(f"Gxy from lib: {Gxy_actual[:16]}...")
expected_g = (Gx_bytes + Gy_bytes).hex().lower()
print(f"期望 Gxy:     {expected_g[:16]}...")
print(f"G 一致: {Gxy_actual == expected_g}")

print("\n" + "=" * 60)
print("方案3: 用 gmssl-python 的 _sm3_z 实现（data 为 content_bytes）")
print("=" * 60)
# _sm3_z 的实现：
# M_ = (Za + data.hex()).encode('utf-8')
# e = sm3(unhex(M_))
# 这意味着 M_ = bytes(Za_hex + content_bytes.hex(), utf-8)
# 然后 unhexlify 得到实际的字节
Za_str = Za2.hex()
data_hex_str = content_bytes.hex()  # 把228字节UTF-8内容再编码为HEX
M_str = Za_str + data_hex_str
print(f"Za.hex() + content_bytes.hex() 总长度: {len(M_str)} 字符")
print(f"=> unhexlify 后为 {len(M_str)//2} 字节")
dgst_gmssl_py = sm3_hash_bytes(binascii.a2b_hex(M_str))
print(f"gmssl-python 方式哈希: {dgst_gmssl_py.hex()}")
r3 = sm2_obj.verify(sig_raw_hex, dgst_gmssl_py.hex())
print(f"验签: {r3}")

print("\n" + "=" * 60)
print("方案4: Java SM2Signer 内部实际使用 data 的字节")
print("确认 SM2Signer.update(content, ...) 传入的是什么")
print("如果 content = CT_HEX.getBytes('UTF-8')，")
print("则 Java 签名 = SM2(SM3(Z || CT_HEX.getBytes('UTF-8')))")
print("= 方案1，但方案1验签=False，说明有其他差异")
print("=" * 60)

# 让我们试试不同的 USER_ID
print("\n尝试不同的 USER_ID...")
for uid_str in ["1234567812345678", "31323334353637383132333435363738"]:
    uid_bytes = uid_str.encode('utf-8') if len(uid_str) <= 20 else bytes.fromhex(uid_str)
    entl = (len(uid_bytes) * 8).to_bytes(2, 'big')
    zi = entl + uid_bytes + a_bytes + b_bytes + Gx_bytes + Gy_bytes + px_bytes + py_bytes
    zi_hash = sm3_hash_bytes(zi)
    dgst_i = sm3_hash_bytes(zi_hash + content_bytes)
    ri = sm2_obj.verify(sig_raw_hex, dgst_i.hex())
    print(f"  USER_ID={uid_str!r}: Z={zi_hash.hex()[:16]}... 验签={ri}")

print("\n" + "=" * 60)
print("方案5: 检查 Java 是否签的是 content_bytes 的 HEX 表示")
print("即 sign(CT_HEX.getBytes()) 对应的content是CT_HEX字符串")
print("= SM3(Z || CT_HEX_AS_UTF8) - 就是方案1")
print("也许问题在于 Java 实际传给 sm2Signer.update 的不是 UTF-8?")
print("=" * 60)

# 如果 Java 签的是 CT_HEX 字符串的 bytes（不做任何转换）
# String.getBytes() 默认平台编码，但通常是 UTF-8
# 对于纯 ASCII，UTF-8 = ASCII
print(f"CT_HEX 是否纯ASCII: {all(c < 128 for c in content_bytes)}")
print(f"UTF-8 == ASCII 这里: True (纯ASCII内容)")

print("\n" + "=" * 60)
print("排查: 是否 Java 实际传入了 CT_HEX 的二进制（把HEX解码后的字节）?")
print("即 sign(HexDecode(CT_HEX)) 而不是 sign(CT_HEX.getBytes())")
print("=" * 60)
ct_binary = bytes.fromhex(CT_HEX)  # 114字节
dgst5 = sm3_hash_bytes(Z + ct_binary)
print(f"SM3(Z || HexDecode(CT_HEX)): {dgst5.hex()}")
r5 = sm2_obj.verify(sig_raw_hex, dgst5.hex())
print(f"验签: {r5}")

print("\n" + "=" * 60)
print("排查: GmSSL sm2_compute_z 参数顺序是否与标准一致")
print("GmSSL: sm2_compute_z(z, public_key, id, idlen)")  
print("SM2 标准 Z: SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)")
print("=" * 60)
# GmSSL 源码中 sm2_compute_z 的实现应该是标准的
# 我们已经在 C debug 中打印了 Z，让我们用那个值
KNOWN_Z_FROM_C = "fb23ae08d4d3c8d76b9ee3a0f7741547d2d4888f2e0f9f2fb56a9f0a24910fb40"
# （上次调试输出的Z值）
try:
    Z_from_c = bytes.fromhex(KNOWN_Z_FROM_C)
    dgst_c = sm3_hash_bytes(Z_from_c + content_bytes)
    rc = sm2_obj.verify(sig_raw_hex, dgst_c.hex())
    print(f"用C端Z值 {KNOWN_Z_FROM_C[:16]}... 验签={rc}")
except Exception as e:
    print(f"C端Z值长度={len(KNOWN_Z_FROM_C)}, 错误: {e}")

print(f"我们计算的Z: {Z.hex()}")
print(f"C端Z值:      {KNOWN_Z_FROM_C}")
print(f"一致: {Z.hex() == KNOWN_Z_FROM_C.lower()}")

print("\n" + "=" * 60)
print("最终诊断：尝试用 cryptography 库做 SM2 ECDSA 验签")
print("（使用通用 ECDSA 数学）")
print("=" * 60)
try:
    # SM2 实际上是特化的 ECDSA，可以用通用 ECDSA 数学验证
    # 但需要 SM2 曲线参数
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey, ECDSA, EllipticCurvePublicNumbers
    )
    # SM2 不在标准库中，跳过
    print("cryptography 库不支持 SM2 曲线，跳过")
except Exception as e:
    print(f"跳过: {e}")

print("\n完成!")
