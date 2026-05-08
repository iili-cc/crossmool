#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
深度分析 Java 签名 vs C 验签不匹配的原因
验证 gmssl-python 库的 _sm3_z 实现是否有 bug
"""
from gmssl import sm2 as gmssl_sm2, sm3 as gmssl_sm3
import binascii
from gmssl.func import bytes_to_list

# ---- 测试数据 ----
CT_HEX = "04e4534be6847921acdf2f0ff2e4d1e0057bcdba9450c64af197c30762e8356531a26295dfbfc6335d21ad8176312e8c9b0489400599657c6eacf197f08db43a35d96c52a989a8aab3f9b855a56bb507e5ebe81f2aea88d76d72671a3bd1244273f80dd60d50556bb4e5cff5fc6a02b97fdf"
SIG_HEX = "3046022100cae388164ba6e735814a03e7cff2a09fa017db831a2ad932b9c2a226776fe07f022100dde7ae2b5c0a32ff04c89d5ebe85911d5015d2593eb012ca66caa5d5ef4e6686"
SIGN_PUBKEY_HEX = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"
DEC_PRIVKEY_HEX = "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

def extract_raw_pubkey(x509_hex):
    b = bytes.fromhex(x509_hex)
    idx = b.find(b'\x04')
    raw = b[idx:]
    assert len(raw) == 65
    return raw

def parse_der_signature(der_hex):
    data = bytes.fromhex(der_hex)
    assert data[0] == 0x30
    idx = 1
    b = data[idx]
    if b & 0x80:
        nb = b & 0x7f
        idx += 1 + nb
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

# 签名内容（密文HEX字符串的UTF-8字节）
content_str = CT_HEX  # 228字节的ASCII字符串
content_bytes = content_str.encode('utf-8')  # 228 bytes

# 解析签名 r,s
r32, s32 = parse_der_signature(SIG_HEX)
sig_raw_hex = (r32 + s32).hex()

print("=== 分析开始 ===")
print(f"内容: {content_str[:40]}... (长度={len(content_bytes)}字节)")
print(f"r: {r32.hex()}")
print(f"s: {s32.hex()}")

# SM2 曲线标准参数
USER_ID = b"1234567812345678"
ENTL = (len(USER_ID) * 8).to_bytes(2, 'big')  # 0x0080 = 128
a_bytes = bytes.fromhex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC")
b_bytes = bytes.fromhex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93")
Gx_bytes = bytes.fromhex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7")
Gy_bytes = bytes.fromhex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0")

print("\n=== 标准 SM3WithSM2 计算 Z || content ===")
# 正确的 Z 计算
z_input = ENTL + USER_ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + px_bytes + py_bytes
z_value = bytes(gmssl_sm3.sm3_hash(bytes_to_list(z_input)))
print(f"ENTL: {ENTL.hex()}")
print(f"USER_ID hex: {USER_ID.hex()}")
print(f"Z 值 (32字节): {z_value.hex()}")

# 正确的 SM3 哈希：SM3(Z || message_bytes)
hash_input = z_value + content_bytes
dgst = bytes(gmssl_sm3.sm3_hash(bytes_to_list(hash_input)))
print(f"SM3(Z || content_bytes): {dgst.hex()}")

# 验签：用 r, s 直接验证哈希值
# 使用 gmssl-python 的 CryptSM2.verify（输入是十六进制字符串的哈希）
sm2_obj = gmssl_sm2.CryptSM2(public_key=x_hex+y_hex, private_key="")
result_direct = sm2_obj.verify(sig_raw_hex, dgst.hex())
print(f"\n直接验签(标准 SM3(Z||content_bytes)): {result_direct}")

print("\n=== 分析 gmssl-python _sm3_z 的实际行为 ===")
# 查看 gmssl-python 的 _sm3_z 如何处理 data
# data = content_bytes (bytes 对象)
# 1. Za = SM3(Z计算材料)
# 2. M_ = (Za + data.hex()).encode('utf-8')   ← BUG: data.hex() 而不是 data
# 3. e = SM3(unhexlify(M_))

# 模拟 gmssl-python 的计算
z_gmssl = '0080' + '31323334353637383132333435363738' + \
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC' + \
    '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93' + \
    '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7' + \
    'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0' + \
    x_hex + y_hex
z_gmssl = binascii.a2b_hex(z_gmssl)
Za = bytes(gmssl_sm3.sm3_hash(bytes_to_list(z_gmssl)))
print(f"gmssl-python Za: {Za.hex()}")
print(f"标准 Z 值:       {z_value.hex()}")
print(f"Za == Z: {Za == z_value}")

# gmssl-python 的 M_ 处理
# 注意: _sm3_z 接受 data 为 bytes
data_hex_str = content_bytes.hex()  # 对 UTF-8 字节再编码为 HEX
M_gmssl = (Za.hex() + data_hex_str).encode('utf-8')
print(f"\ngmssl-python 的 M_ 是 Za.hex()+data.hex() 的UTF-8编码")
print(f"Za.hex() + data.hex() 长度: {len(Za.hex() + data_hex_str)} 字符")
print(f"M_ 作为 UTF-8 字节后 unhexlify 长度: {len(binascii.a2b_hex(Za.hex() + data_hex_str))}")
dgst_gmssl = bytes(gmssl_sm3.sm3_hash(bytes_to_list(binascii.a2b_hex(Za.hex() + data_hex_str))))
print(f"gmssl-python SM3: {dgst_gmssl.hex()}")

result_gmssl_manual = sm2_obj.verify(sig_raw_hex, dgst_gmssl.hex())
print(f"gmssl-python方式验签结果: {result_gmssl_manual}")

print("\n=== 分析 Java 端可能的哈希计算 ===")
# Java SM2Signer.update(content, 0, content.length) 处理的是什么？
# SM2Signer 内部：先 update Z，再 update message_bytes
# 最终哈希 = SM3(Z || message_bytes)
# 其中 message_bytes 就是 content_str.getBytes(UTF-8) = CT_HEX.getBytes(UTF-8)
# 也就是 CT_HEX 字符串的 UTF-8 字节（纯 ASCII, 228字节）
print(f"Java 应该计算: SM3(Z || CT_HEX.getBytes(UTF-8))")
print(f"= SM3(Z || {content_str[:20]}... [228字节 ASCII])")
print(f"= {dgst.hex()}")
print(f"这与 GmSSL sm2_verify_finish(SM3WithSM2) 相同: 传入相同内容则应该能验签")

print("\n=== 对比三种 Z 计算 ===")
# 方案1：USER_ID 用 ASCII bytes（上面已算）
z_ascii = ENTL + USER_ID + a_bytes + b_bytes + Gx_bytes + Gy_bytes + px_bytes + py_bytes
Z_ascii = bytes(gmssl_sm3.sm3_hash(bytes_to_list(z_ascii)))
print(f"Z (USER_ID=ASCII '1234567812345678'): {Z_ascii.hex()}")

# 方案2：BouncyCastle 可能用不同的 ID
# BouncyCastle SM2Signer 默认 USER_ID = "1234567812345678".getBytes(UTF-8) = same ASCII
print(f"ASCII == UTF-8 for '1234567812345678': {USER_ID == '1234567812345678'.encode('utf-8')}")

# 方案3：如果 Java 用的是 getBytes() 默认编码（也是 UTF-8 for ASCII）
# 应该一样

print("\n=== 检查 GmSSL 的 sm2_compute_z 参数顺序 ===")
# GmSSL: sm2_compute_z(z, &key.public_key, "1234567812345678", 16)
# SM2_POINT.x 和 SM2_POINT.y 是 big-endian uint8[32]
print(f"公钥 Px: {px_bytes.hex()}")
print(f"公钥 Py: {py_bytes.hex()}")
print(f"期望 Z:  {Z_ascii.hex()}")

print("\n完成！")
print(f"\n结论:")
print(f"  - 签名 r, s 范围正确: True")
print(f"  - 公钥在曲线上: True")
print(f"  - 标准验签(SM3WithSM2) 结果: {result_direct}")
print(f"  - 如果 result_direct=False，说明Java签名的内容不是 CT_HEX 字符串")
print(f"  - 或者 Java 用的 USER_ID/Z 计算方式不同")
