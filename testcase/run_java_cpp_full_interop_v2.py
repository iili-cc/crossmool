#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java ↔ C++ SM2/SM3/SM4 双向互通性测试编排脚本 v2

覆盖 12 条双向互通测试 + SM3/HMAC-SM4 比对，每条 3 种文本类型。
"""

import json
import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime

# ============================================================
# 路径配置
# ============================================================
BASE_DIR    = Path("G:/workspaces/git/corssmool/crossmool")
CPP_EXE     = BASE_DIR / "cpp/crossmool/build/bin/Release/interoperability_test.exe"
JAVA_DIR    = BASE_DIR / "testcase/java_test_classes"
JAVA_CLASSES = BASE_DIR / "java/crossmool/target/classes"
JAVA_DEPS   = BASE_DIR / "java/crossmool/target/dependency"
TEMP_DIR    = BASE_DIR / "testcase/.interop_temp"
RESULT_DIR  = BASE_DIR / "testcase/results"

JAVA_CP = (
    f"{JAVA_DIR};{JAVA_CLASSES};"
    f"{JAVA_DEPS}/bcprov-jdk18on-1.82.jar;"
    f"{JAVA_DEPS}/lombok-1.18.42.jar;"
    f"{JAVA_DEPS}/slf4j-api-2.0.17.jar;"
    f"{JAVA_DEPS}/logback-classic-1.5.22.jar;"
    f"{JAVA_DEPS}/logback-core-1.5.22.jar"
)

TEST_MESSAGES = [
    "Hello, Cross-Language Interop Test!",
    "国密算法跨语言互通测试：简体中文",
    "Mixed content 123!@#$% 混合測試數據",
]
HMAC_KEY_HEX = "0123456789abcdef0123456789abcdef"
FIXED_SM4_KEY = "8091d00c09ba74cfe6da26b7daa7ce39"

results = []
pass_count = fail_count = 0

# ============================================================
# 工具函数
# ============================================================

def run_java(args, timeout=60):
    """返回 (ok, stdout_data)"""
    cmd = ["java", "-cp", JAVA_CP, "java_test_classes.JavaCLIHelper"] + args
    try:
        r = subprocess.run(cmd, cwd=str(BASE_DIR / "testcase"),
                           capture_output=True, text=True, timeout=timeout,
                           encoding='utf-8', errors='replace')
        out = r.stdout
        stderr = r.stderr
        if "__RESULT_OK__" in out:
            data = out[:out.index("__RESULT_OK__")].strip()
            return True, data
        if r.returncode != 0:
            return False, f"exit={r.returncode}: {stderr[:200]}"
        return True, out.strip()
    except Exception as e:
        return False, str(e)

def run_cpp(args, timeout=60):
    """返回 (ok, stdout, stderr)"""
    cmd = [str(CPP_EXE)] + args
    try:
        r = subprocess.run(cmd, cwd=str(TEMP_DIR),
                           capture_output=True, text=True, timeout=timeout,
                           encoding='utf-8', errors='replace')
        return r.returncode == 0, r.stdout, r.stderr
    except Exception as e:
        return False, "", str(e)

def write_temp(filename, content):
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    path = TEMP_DIR / filename
    # 始终写入 raw string，不额外编码
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    return str(path)

def read_temp(filename):
    with open(TEMP_DIR / filename, 'r', encoding='utf-8') as f:
        return f.read()

def read_temp_json(filename):
    with open(TEMP_DIR / filename, 'r', encoding='utf-8') as f:
        return json.load(f)

def json_dumps(obj):
    """JSON 序列化，保留中文原始字符（不转义为 \\uXXXX）"""
    return json.dumps(obj, ensure_ascii=False, indent=2)

def mk_keys(enc_pub=None, enc_prv=None, sign_pub=None, sign_prv=None):
    """构建 interoperability_test.exe 需要的 nested JSON key 格式"""
    d = {}
    if enc_pub: d["encryption_public_key"] = {"hex": enc_pub}
    if enc_prv: d["encryption_private_key"] = {"hex": enc_prv}
    if sign_pub: d["signature_public_key"] = {"hex": sign_pub}
    if sign_prv: d["signature_private_key"] = {"hex": sign_prv}
    return d

# ============================================================
# DER → C1C3C2 转换（GmSSL SM2Cipher DER → Java RAW C1C3C2）
# GmSSL DER: 30||len||02||Lx||x||02||Ly||y||04||20||C3||04||Lc2||C2
# C1C3C2:    04 || x[32] || y[32] || C3[32] || C2[N]
# ============================================================
def der_to_c1c3c2(der_hex):
    """将 GmSSL DER SEQUENCE 密文转换为 Java C1C3C2 RAW 格式"""
    data = bytes.fromhex(der_hex)
    if len(data) < 2 or data[0] != 0x30:
        raise ValueError(f"Not DER: first byte 0x{data[0]:02x}")
    pos = 2
    if data[1] >= 0x80:
        pos += data[1] - 0x80

    def read_tlv(tag):
        nonlocal pos
        if data[pos] != tag:
            raise ValueError(f"Expected tag 0x{tag:02x} at pos {pos}, got 0x{data[pos]:02x}")
        pos += 1
        length = data[pos]; pos += 1
        if length >= 0x80:
            extra = length - 0x80
            length = int.from_bytes(data[pos:pos+extra], 'big')
            pos += extra
        val = data[pos:pos+length]
        pos += length
        return val

    x_raw = read_tlv(0x02)  # INTEGER x
    y_raw = read_tlv(0x02)  # INTEGER y
    c3 = read_tlv(0x04)     # OCTET STRING C3
    c2 = read_tlv(0x04)     # OCTET STRING C2

    # Strip ASN.1 INTEGER leading 0x00 sign byte, then pad to 32 bytes
    def integer_to_32(val):
        while len(val) > 1 and val[0] == 0x00:
            val = val[1:]
        if len(val) > 32:
            raise ValueError(f"INTEGER too long: {len(val)} bytes")
        if len(val) < 32:
            val = b'\x00' * (32 - len(val)) + val
        return val

    x = integer_to_32(x_raw)
    y = integer_to_32(y_raw)
    if len(c3) < 32:
        c3 = b'\x00' * (32 - len(c3)) + c3

    return (b'\x04' + x + y + c3 + c2).hex()

# ============================================================
# 结果记录
# ============================================================
def record(algo, op, direction, status, details=""):
    global pass_count, fail_count
    if status == "PASS": pass_count += 1
    else: fail_count += 1
    results.append({"algorithm": algo, "operation": op, "direction": direction,
                    "status": status, "details": details})
    ico = "PASS" if status == "PASS" else "FAIL"
    print(f"  [{ico}] {algo} {op} ({direction}): {details}")

# ============================================================
# Phase 1: 生成 SM2 密钥对
# ============================================================
print("=" * 60)
print("Phase 1: Generate SM2 Key Pair (Java)")
print("=" * 60)

ok, data = run_java(["gen-keypair"])
if not ok: sys.exit("FATAL: gen-keypair failed")
ki = json.loads(data)
SM2_PUB = ki["public_key"]
SM2_PRV = ki["private_key"]
print(f"  Public:  {SM2_PUB[:40]}...")
print(f"  Private: {SM2_PRV[:40]}...")

# ============================================================
# Phase 2: SM2 加密/解密 双向
# ============================================================
print("\n" + "=" * 60)
print("Phase 2: SM2 Encrypt/Decrypt Bidirectional")
print("=" * 60)

for i, msg in enumerate(TEST_MESSAGES):
    short = msg[:30].replace('\n', '\\n')

    # --- Java Encrypt → C++ Decrypt ---
    ok_j, java_ct = run_java(["sm2-encrypt", msg, SM2_PUB])
    if ok_j:
        ct_input = json_dumps({"ciphertext_hex": java_ct})
        write_temp("ct.json", ct_input)
        write_temp("keys_enc.json", json_dumps(mk_keys(enc_prv=SM2_PRV)))
        ok_c, _, cerr = run_cpp(["decrypt", str(TEMP_DIR/"ct.json"), str(TEMP_DIR/"keys_enc.json"), str(TEMP_DIR/"out.json")])
        if ok_c:
            out = read_temp_json("out.json")
            record("SM2", "enc/dec", "Java→C++",
                   "PASS" if out.get("plaintext","") == msg else "FAIL",
                   f"#{i+1} {short}" + (f" [got:{out.get('plaintext','')[:20]}]" if out.get("plaintext","") != msg else ""))
        else:
            record("SM2", "enc/dec", "Java→C++", "FAIL", f"#{i+1} {short} C++: {cerr[:100]}")
    else:
        record("SM2", "enc/dec", "Java→C++", "FAIL", f"#{i+1} Java err: {java_ct[:100]}")

    # --- C++ Encrypt → Java Decrypt ---
    write_temp("pt.txt", msg)
    write_temp("keys_enc2.json", json_dumps(mk_keys(enc_pub=SM2_PUB)))
    ok_c, _, cerr = run_cpp(["encrypt", str(TEMP_DIR/"pt.txt"), str(TEMP_DIR/"keys_enc2.json"), str(TEMP_DIR/"enc_out.json")])
    if ok_c:
        enc_out = read_temp_json("enc_out.json")
        cpp_ct_der = enc_out.get("ciphertext_hex", "")
        # 转换 DER → C1C3C2 供 Java 解密
        try:
            cpp_ct = der_to_c1c3c2(cpp_ct_der)
        except Exception as e:
            record("SM2", "enc/dec", "C++→Java", "FAIL", f"#{i+1} DER→C1C3C2 err: {e}")
            continue
        ok_j, java_pt = run_java(["sm2-decrypt", cpp_ct, SM2_PRV])
        record("SM2", "enc/dec", "C++→Java",
               "PASS" if ok_j and java_pt == msg else "FAIL",
               f"#{i+1} {short}" + (f" [got:{java_pt[:20]}]" if ok_j and java_pt != msg else ""))
    else:
        record("SM2", "enc/dec", "C++→Java", "FAIL", f"#{i+1} C++ err: {cerr[:100]}")

# ============================================================
# Phase 3: SM2 签名/验签 双向
# ============================================================
print("\n" + "=" * 60)
print("Phase 3: SM2 Sign/Verify Bidirectional")
print("=" * 60)

for i, msg in enumerate(TEST_MESSAGES):
    short = msg[:30].replace('\n', '\\n')

    # --- Java Sign → C++ Verify ---
    ok_j, java_sig = run_java(["sm2-sign", msg, SM2_PRV])
    if ok_j:
        vin = json_dumps({"content": msg, "signature_hex": java_sig})
        write_temp("ver_in.json", vin)
        write_temp("keys_sig.json", json_dumps(mk_keys(sign_pub=SM2_PUB)))
        ok_c, _, cerr = run_cpp(["verify", str(TEMP_DIR/"ver_in.json"), str(TEMP_DIR/"keys_sig.json"), str(TEMP_DIR/"ver_out.json")])
        if ok_c:
            out = read_temp_json("ver_out.json")
            record("SM2", "sign/verify", "Java→C++",
                   "PASS" if out.get("verify_result") == True else "FAIL",
                   f"#{i+1} {short}")
        else:
            record("SM2", "sign/verify", "Java→C++", "FAIL", f"#{i+1} C++ err: {cerr[:100]}")
    else:
        record("SM2", "sign/verify", "Java→C++", "FAIL", f"#{i+1} Java err: {java_sig[:100]}")

    # --- C++ Sign → Java Verify ---
    write_temp("sign_pt.txt", msg)
    write_temp("keys_sign.json", json_dumps(mk_keys(sign_prv=SM2_PRV)))
    ok_c, _, cerr = run_cpp(["sign", str(TEMP_DIR/"sign_pt.txt"), str(TEMP_DIR/"keys_sign.json"), str(TEMP_DIR/"sign_out.json")])
    if ok_c:
        out = read_temp_json("sign_out.json")
        cpp_sig = out.get("signature_hex", "")
        ok_j, java_ver = run_java(["sm2-verify", msg, cpp_sig, SM2_PUB])
        record("SM2", "sign/verify", "C++→Java",
               "PASS" if ok_j and java_ver.strip().lower() == "true" else "FAIL",
               f"#{i+1} {short}" + (f" [Java:{java_ver[:50]}]" if ok_j and java_ver.strip().lower() != "true" else ""))
    else:
        record("SM2", "sign/verify", "C++→Java", "FAIL", f"#{i+1} C++ err: {cerr[:100]}")

# ============================================================
# Phase 4: SM2 EncryptSign / VerifyDecrypt 双向
# ============================================================
print("\n" + "=" * 60)
print("Phase 4: SM2 EncryptSign / VerifyDecrypt Bidirectional")
print("=" * 60)

for i, msg in enumerate(TEST_MESSAGES):
    short = msg[:30].replace('\n', '\\n')

    # --- Java Encrypt+Sign → C++ Verify+Decrypt ---
    ok_e, java_ct = run_java(["sm2-encrypt", msg, SM2_PUB])
    ok_s, java_sig = run_java(["sm2-sign", java_ct if ok_e else msg, SM2_PRV])
    if ok_e and ok_s:
        vd_in = json_dumps({"ciphertext_hex": java_ct, "signature_hex": java_sig})
        vd_keys = mk_keys(enc_prv=SM2_PRV, sign_pub=SM2_PUB)
        write_temp("vd_in.json", vd_in)
        write_temp("vd_keys.json", json_dumps(vd_keys))
        ok_c, _, cerr = run_cpp(["verify_decrypt", str(TEMP_DIR/"vd_in.json"), str(TEMP_DIR/"vd_keys.json"), str(TEMP_DIR/"vd_out.json")])
        if ok_c:
            out = read_temp_json("vd_out.json")
            ok = out.get("verify_result") == True and out.get("decrypted_text") == msg
            record("SM2", "enc_sign/ver_dec", "Java→C++", "PASS" if ok else "FAIL",
                   f"#{i+1} {short}" + (f" v={out.get('verify_result')} t={out.get('decrypted_text','')[:20]}" if not ok else ""))
        else:
            record("SM2", "enc_sign/ver_dec", "Java→C++", "FAIL", f"#{i+1} C++: {cerr[:100]}")
    else:
        record("SM2", "enc_sign/ver_dec", "Java→C++", "FAIL", f"#{i+1} Java err")

    # --- C++ EncryptSign → Java Verify+Decrypt ---
    write_temp("es_pt.txt", msg)
    es_keys = mk_keys(enc_pub=SM2_PUB, sign_prv=SM2_PRV)
    write_temp("es_keys.json", json_dumps(es_keys))
    ok_c, _, cerr = run_cpp(["encrypt_sign", str(TEMP_DIR/"es_pt.txt"), str(TEMP_DIR/"es_keys.json"), str(TEMP_DIR/"es_out.json")])
    if ok_c:
        out = read_temp_json("es_out.json")
        cpp_ct_der = out.get("ciphertext_hex", "")
        cpp_sig = out.get("signature_hex", "")
        try:
            cpp_ct = der_to_c1c3c2(cpp_ct_der)
        except Exception as e:
            record("SM2", "enc_sign/ver_dec", "C++→Java", "FAIL", f"#{i+1} DER→C1C3C2: {e}")
            continue
        # C++ signs the HEX STRING of the DER ciphertext (UTF-8 bytes of "306f...")
        # So Java must verify the hex string, not the decoded DER bytes
        ok_v, jv = run_java(["sm2-verify", cpp_ct_der, cpp_sig, SM2_PUB])
        if ok_v and jv.strip().lower() == "true":
            ok_d, jp = run_java(["sm2-decrypt", cpp_ct, SM2_PRV])
            record("SM2", "enc_sign/ver_dec", "C++→Java",
                   "PASS" if ok_d and jp == msg else "FAIL",
                   f"#{i+1} {short}" + (f" [dec:{jp[:20]}]" if ok_d and jp != msg else ""))
        else:
            record("SM2", "enc_sign/ver_dec", "C++→Java", "FAIL",
                   f"#{i+1} {short} verify={jv[:50]}")
    else:
        record("SM2", "enc_sign/ver_dec", "C++→Java", "FAIL", f"#{i+1} C++: {cerr[:100]}")

# ============================================================
# Phase 5: SM3 Digest 双向比对
# ============================================================
print("\n" + "=" * 60)
print("Phase 5: SM3 Digest Bidirectional Comparison")
print("=" * 60)

for i, msg in enumerate(TEST_MESSAGES):
    short = msg[:30].replace('\n', '\\n')
    ok_j, java_sm3 = run_java(["sm3-digest", msg])
    write_temp("sm3_pt.txt", msg)
    ok_c, _, cerr = run_cpp(["sm3_digest", str(TEMP_DIR/"sm3_pt.txt"), str(TEMP_DIR/"sm3_out.json")])
    if ok_c:
        out = read_temp_json("sm3_out.json")
        cpp_sm3 = out.get("digest_hex", "")
        record("SM3", "digest", "Java↔C++",
               "PASS" if java_sm3 == cpp_sm3 else "FAIL",
               f"#{i+1} {short} J={java_sm3[:12]}... C={cpp_sm3[:12]}...")
    else:
        record("SM3", "digest", "Java↔C++", "FAIL", f"#{i+1} C++: {cerr[:100]}")

# ============================================================
# Phase 6: HMAC-SM3 双向比对
# ============================================================
print("\n" + "=" * 60)
print("Phase 6: HMAC-SM3 Bidirectional Comparison")
print("=" * 60)

for i, msg in enumerate(TEST_MESSAGES):
    short = msg[:30].replace('\n', '\\n')
    ok_j, java_hmac = run_java(["sm3-hmac", HMAC_KEY_HEX, msg])
    hmac_in = json_dumps({"hmac_key_hex": HMAC_KEY_HEX, "data": msg})
    write_temp("hmac_in.json", hmac_in)
    ok_c, _, cerr = run_cpp(["sm3_hmac", str(TEMP_DIR/"hmac_in.json"), str(TEMP_DIR/"hmac_out.json")])
    if ok_c:
        out = read_temp_json("hmac_out.json")
        cpp_hmac = out.get("hmac_hex", "")
        record("HMAC-SM3", "hmac", "Java↔C++",
               "PASS" if java_hmac == cpp_hmac else "FAIL",
               f"#{i+1} {short} J={java_hmac[:12]}... C={cpp_hmac[:12]}...")
    else:
        record("HMAC-SM3", "hmac", "Java↔C++", "FAIL", f"#{i+1} C++: {cerr[:100]}")

# ============================================================
# Phase 7: SM4 Encrypt/Decrypt 双向
# ============================================================
print("\n" + "=" * 60)
print("Phase 7: SM4 Encrypt/Decrypt Bidirectional")
print("=" * 60)

for i, msg in enumerate(TEST_MESSAGES):
    short = msg[:30].replace('\n', '\\n')

    # --- Java Encrypt → C++ Decrypt ---
    ok_j, sm4_jct = run_java(["sm4-encrypt", msg, FIXED_SM4_KEY])
    if ok_j:
        in_j = json_dumps({"ciphertext_hex": sm4_jct, "sm4_key_hex": FIXED_SM4_KEY})
        write_temp("sm4_jdec.json", in_j)
        ok_c, _, cerr = run_cpp(["sm4_decrypt", str(TEMP_DIR/"sm4_jdec.json"), str(TEMP_DIR/"sm4_out.json")])
        if ok_c:
            out = read_temp_json("sm4_out.json")
            record("SM4", "enc/dec", "Java→C++",
                   "PASS" if out.get("plaintext","") == msg else "FAIL",
                   f"#{i+1} {short}" + (f" [got:{out.get('plaintext','')[:20]}]" if out.get("plaintext","") != msg else ""))
        else:
            record("SM4", "enc/dec", "Java→C++", "FAIL", f"#{i+1} C++: {cerr[:100]}")
    else:
        record("SM4", "enc/dec", "Java→C++", "FAIL", f"#{i+1} Java: {sm4_jct[:100]}")

    # --- C++ Encrypt → Java Decrypt ---
    in_c = json_dumps({"plaintext": msg, "sm4_key_hex": FIXED_SM4_KEY})
    write_temp("sm4_cenc.json", in_c)
    ok_c, _, cerr = run_cpp(["sm4_encrypt", str(TEMP_DIR/"sm4_cenc.json"), str(TEMP_DIR/"sm4_enc_out.json")])
    if ok_c:
        out = read_temp_json("sm4_enc_out.json")
        sm4_cct = out.get("ciphertext_hex", "")
        ok_j, jp = run_java(["sm4-decrypt", sm4_cct, FIXED_SM4_KEY])
        record("SM4", "enc/dec", "C++→Java",
               "PASS" if ok_j and jp == msg else "FAIL",
               f"#{i+1} {short}" + (f" [got:{jp[:20]}]" if ok_j and jp != msg else ""))
    else:
        record("SM4", "enc/dec", "C++→Java", "FAIL", f"#{i+1} C++: {cerr[:100]}")

# ============================================================
# 结果汇总
# ============================================================
total = pass_count + fail_count
print("\n" + "=" * 60)
print("FINAL SUMMARY")
print("=" * 60)
print(f"  Total:  {total}")
print(f"  PASS:   {pass_count}")
print(f"  FAIL:   {fail_count}")
print(f"  Rate:   {pass_count / total * 100:.1f}%" if total > 0 else "  Rate: N/A")

RESULT_DIR.mkdir(parents=True, exist_ok=True)
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
rfile = RESULT_DIR / f"java_cpp_full_interop_{ts}.json"
with open(rfile, 'w', encoding='utf-8') as f:
    json.dump({
        "time": datetime.now().isoformat(),
        "total": total, "passed": pass_count, "failed": fail_count,
        "rate": f"{pass_count/total*100:.1f}%" if total > 0 else "N/A",
        "sm2_public": SM2_PUB, "results": results
    }, f, indent=2, ensure_ascii=False)
print(f"\nResults: {rfile}")
sys.exit(0 if fail_count == 0 else 1)
