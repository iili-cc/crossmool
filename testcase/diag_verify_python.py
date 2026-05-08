#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用 gmssl (Python 3.2.2) 验证 Java 签名
排查 C 侧验签失败的根本原因
"""

# ---- 测试数据（来自 test_1_simple_text.json）----
CT_HEX = "04e4534be6847921acdf2f0ff2e4d1e0057bcdba9450c64af197c30762e8356531a26295dfbfc6335d21ad8176312e8c9b0489400599657c6eacf197f08db43a35d96c52a989a8aab3f9b855a56bb507e5ebe81f2aea88d76d72671a3bd1244273f80dd60d50556bb4e5cff5fc6a02b97fdf"
SIG_HEX = "3046022100cae388164ba6e735814a03e7cff2a09fa017db831a2ad932b9c2a226776fe07f022100dde7ae2b5c0a32ff04c89d5ebe85911d5015d2593eb012ca66caa5d5ef4e6686"
# X.509 SubjectPublicKeyInfo DER (hex)
SIGN_PUBKEY_HEX = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"

# ---- 提取裸公钥（04||x||y）----
def extract_raw_pubkey(x509_hex):
    """从 X.509 SubjectPublicKeyInfo DER 中提取 04||x||y (65字节)"""
    b = bytes.fromhex(x509_hex)
    # 找到 04 字节（非压缩点标识符）
    idx = b.find(b'\x04')
    if idx == -1:
        raise ValueError("找不到 04 标识符")
    raw = b[idx:]
    if len(raw) != 65:
        raise ValueError(f"公钥长度异常: {len(raw)}, 期望65")
    return raw

# ---- 解析 DER 签名 → (r, s) 整数 ----
def parse_der_signature(der_hex):
    """解析 DER 编码签名，返回 (r_bytes_32, s_bytes_32)"""
    data = bytes.fromhex(der_hex)
    assert data[0] == 0x30, "不是 SEQUENCE"
    
    # 跳过 SEQUENCE 头
    idx = 1
    seq_len_byte = data[idx]
    if seq_len_byte & 0x80:
        nb = seq_len_byte & 0x7f
        idx += 1 + nb
    else:
        idx += 1
    
    # 解析 INTEGER r
    assert data[idx] == 0x02, "期望 INTEGER"
    idx += 1
    r_len = data[idx]; idx += 1
    r_bytes = data[idx:idx+r_len]; idx += r_len
    
    # 解析 INTEGER s
    assert data[idx] == 0x02, "期望 INTEGER"
    idx += 1
    s_len = data[idx]; idx += 1
    s_bytes = data[idx:idx+s_len]
    
    # 转换为 32 字节（去掉前导0x00并左填充）
    r_int = int.from_bytes(r_bytes, 'big')
    s_int = int.from_bytes(s_bytes, 'big')
    r32 = r_int.to_bytes(32, 'big')
    s32 = s_int.to_bytes(32, 'big')
    return r32, s32

# ==== 方法1: 用 gmssl.sm2.CryptSM2 验签 ====
print("=" * 60)
print("方法1: gmssl.sm2.CryptSM2 验签")
print("=" * 60)

try:
    from gmssl import sm2 as gmssl_sm2
    
    raw_pub = extract_raw_pubkey(SIGN_PUBKEY_HEX)
    x_hex = raw_pub[1:33].hex()
    y_hex = raw_pub[33:65].hex()
    print(f"公钥 x: {x_hex}")
    print(f"公钥 y: {y_hex}")
    
    # gmssl CryptSM2 期望 public_key 为 x||y 的十六进制字符串（不含04前缀）
    pub_key_for_gmssl = x_hex + y_hex
    
    # 签名内容：密文HEX字符串的UTF-8字节
    content_bytes = CT_HEX.encode('utf-8')
    print(f"签名内容长度: {len(content_bytes)} 字节")
    print(f"签名内容前60: {content_bytes[:60]}")
    
    # CryptSM2 使用默认 USER_ID
    # 注意: gmssl-python 3.x 的 CryptSM2 verify_with_sm3 方法
    # 对应 SM2Signer with ID
    sm2_obj = gmssl_sm2.CryptSM2(
        public_key=pub_key_for_gmssl,
        private_key=""  # 验签不需要私钥
    )
    
    # 解析签名 DER → r||s (64字节)
    r32, s32 = parse_der_signature(SIG_HEX)
    sig_raw_hex = (r32 + s32).hex()
    print(f"签名 r: {r32.hex()}")
    print(f"签名 s: {s32.hex()}")
    print(f"签名 r||s (hex): {sig_raw_hex}")
    
    # verify_with_sm3: 使用 Z 值（内置 USER_ID = "1234567812345678"）
    try:
        result = sm2_obj.verify_with_sm3(sig_raw_hex, content_bytes)
        print(f"✅ verify_with_sm3 结果: {result}")
    except Exception as e:
        print(f"❌ verify_with_sm3 异常: {e}")
    
    # 也尝试不带Z的验签（sm2_verify）
    try:
        # 手动计算 SM3(Z || content) 并验签
        from gmssl import sm3 as gmssl_sm3
        
        # 计算 Z 值（与 GmSSL 的 sm2_compute_z 一致）
        # Z = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)
        USER_ID = b"1234567812345678"
        ENTL = (len(USER_ID) * 8).to_bytes(2, 'big')
        
        # SM2 曲线参数
        a_hex = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
        b_hex = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
        Gx_hex = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
        Gy_hex = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
        
        z_input = (
            ENTL +
            USER_ID +
            bytes.fromhex(a_hex) +
            bytes.fromhex(b_hex) +
            bytes.fromhex(Gx_hex) +
            bytes.fromhex(Gy_hex) +
            raw_pub[1:33] +  # Px
            raw_pub[33:65]   # Py
        )
        z_value = bytes(gmssl_sm3.sm3_hash(list(z_input)))
        print(f"\nZ 值: {z_value.hex()}")
        
        # 计算 SM3(Z || content)
        hash_input = z_value + content_bytes
        dgst = bytes(gmssl_sm3.sm3_hash(list(hash_input)))
        print(f"SM3(Z||content): {dgst.hex()}")
        
        # 用 sm2_verify 直接验签（不含Z）
        result2 = sm2_obj.verify(sig_raw_hex, dgst.hex())
        print(f"手动Z+SM3后直接 verify 结果: {result2}")
        
    except Exception as e:
        print(f"❌ 手动Z验签异常: {e}")

except Exception as e:
    import traceback
    print(f"❌ 方法1异常: {e}")
    traceback.print_exc()


# ==== 方法2: 用 cryptography 库验签（不含 SM2，仅供参考） ====
print("\n" + "=" * 60)
print("方法2: 纯数学验证 (检查签名格式)")
print("=" * 60)

try:
    # 直接用 ecdsa 库进行纯数学验证
    # 验证 DER 签名格式的 r, s 范围
    r32, s32 = parse_der_signature(SIG_HEX)
    r_int = int.from_bytes(r32, 'big')
    s_int = int.from_bytes(s32, 'big')
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    print(f"n = {hex(n)}")
    print(f"r = {hex(r_int)}")
    print(f"s = {hex(s_int)}")
    print(f"r < n: {r_int < n}")
    print(f"s < n: {s_int < n}")
    print(f"r > 0: {r_int > 0}")
    print(f"s > 0: {s_int > 0}")
    
    # 检查公钥坐标是否在曲线上
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    
    raw_pub = extract_raw_pubkey(SIGN_PUBKEY_HEX)
    px = int.from_bytes(raw_pub[1:33], 'big')
    py = int.from_bytes(raw_pub[33:65], 'big')
    
    lhs = (py * py) % p
    rhs = (px * px * px + a * px + b) % p
    print(f"\n公钥在曲线上: {lhs == rhs} (LHS={lhs}, RHS={rhs})")
    
except Exception as e:
    import traceback
    print(f"❌ 方法2异常: {e}")
    traceback.print_exc()

print("\n完成!")
