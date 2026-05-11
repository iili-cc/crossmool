#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java ↔ C++ SM2/SM3/SM4 双向互通性测试编排脚本

覆盖：
  SM2: encrypt/decrypt 双向, sign/verify 双向, encrypt_sign/verify_decrypt 双向
  SM3: digest 双向比对, hmac 双向比对  
  SM4: encrypt/decrypt 双向
"""

import json
import os
import sys
import subprocess
import time
import re
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

# Java classpath
JAVA_CP = (
    f"{JAVA_DIR};{JAVA_CLASSES};"
    f"{JAVA_DEPS}/bcprov-jdk18on-1.82.jar;"
    f"{JAVA_DEPS}/lombok-1.18.42.jar;"
    f"{JAVA_DEPS}/slf4j-api-2.0.17.jar;"
    f"{JAVA_DEPS}/logback-classic-1.5.22.jar;"
    f"{JAVA_DEPS}/logback-core-1.5.22.jar"
)

# 固定测试数据
TEST_MESSAGES = [
    "Hello, Cross-Language Interop Test!",
    "国密算法跨语言互通测试：简体中文",
    "Mixed content 123!@#$% 混合測試數據",
]
HMAC_KEY_HEX = "0123456789abcdef0123456789abcdef"
FIXED_SM4_KEY = "8091d00c09ba74cfe6da26b7daa7ce39"

# ============================================================
# 工具函数
# ============================================================

def run_java(args, timeout=60):
    """运行 Java CLI helper，返回 (success, output_lines)"""
    cmd = ["java", "-cp", JAVA_CP, "java_test_classes.JavaCLIHelper"] + args
    try:
        result = subprocess.run(
            cmd, cwd=str(BASE_DIR / "testcase"),
            capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace'
        )
        lines = result.stdout.strip().split('\n')
        # Check for __RESULT_OK__ marker
        if "__RESULT_OK__" in result.stdout:
            ok_idx = result.stdout.index("__RESULT_OK__")
            data = result.stdout[:ok_idx].strip()
            return True, data
        if result.returncode != 0:
            print(f"    [JAVA ERR] {result.stderr[:200]}")
            return False, result.stderr
        return True, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:
        return False, str(e)

def run_cpp(args, timeout=60):
    """运行 C++ interoperability_test.exe，返回 (success, stdout, parsed_json)"""
    cmd = [str(CPP_EXE)] + args
    try:
        result = subprocess.run(
            cmd, cwd=str(TEMP_DIR),
            capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace'
        )
        if result.returncode != 0:
            return False, result.stdout, result.stderr
        return True, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def write_temp(filename, content):
    """写入临时文件"""
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    path = TEMP_DIR / filename
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    return str(path)

def read_temp(filename):
    """读取临时文件内容"""
    with open(TEMP_DIR / filename, 'r', encoding='utf-8') as f:
        return f.read()

def read_temp_json(filename):
    """读取临时 JSON 文件"""
    with open(TEMP_DIR / filename, 'r', encoding='utf-8') as f:
        return json.load(f)

def make_keys_json(enc_pub=None, enc_prv=None, sign_pub=None, sign_prv=None):
    """构建 C++ exe 需要的 keys.json 格式"""
    data = {}
    if enc_pub: data["encryption_public_key"] = {"hex": enc_pub}
    if enc_prv: data["encryption_private_key"] = {"hex": enc_prv}
    if sign_pub: data["signature_public_key"] = {"hex": sign_pub}
    if sign_prv: data["signature_private_key"] = {"hex": sign_prv}
    return data

# ============================================================
# 测试结果收集
# ============================================================
results = []
pass_count = 0
fail_count = 0

def record_result(algorithm, operation, direction, status, details=""):
    global pass_count, fail_count
    if status == "PASS": pass_count += 1
    else: fail_count += 1
    results.append({
        "algorithm": algorithm,
        "operation": operation,
        "direction": direction,
        "status": status,
        "details": details
    })
    icon = "PASS" if status == "PASS" else "FAIL"
    print(f"  [{icon}] {algorithm} {operation} ({direction})")

# ============================================================
# 阶段1: 生成密钥对
# ============================================================
print("=" * 60)
print("Phase 1: Generating SM2 Key Pair (Java)")
print("=" * 60)

ok, data = run_java(["gen-keypair"])
if not ok:
    print("FATAL: Failed to generate key pair")
    sys.exit(1)

key_info = json.loads(data)
SM2_PUB = key_info["public_key"]
SM2_PRV = key_info["private_key"]
print(f"  Public Key:  {SM2_PUB[:40]}...")
print(f"  Private Key: {SM2_PRV[:40]}...")

# 这些密钥对加密和签名都用同一对
KEYS_FOR_ENC = make_keys_json(enc_pub=SM2_PUB, enc_prv=SM2_PRV)
KEYS_FOR_SIGN = make_keys_json(sign_pub=SM2_PUB, sign_prv=SM2_PRV)

# ============================================================
# 阶段2: SM2 加密/解密 双向
# ============================================================
print("\n" + "=" * 60)
print("Phase 2: SM2 Encrypt/Decrypt Bidirectional")
print("=" * 60)

for msg in TEST_MESSAGES:
    short = msg[:30].replace('\n', '\\n')

    # ---- Test: Java Encrypt → C++ Decrypt ----
    ok_j, java_ct = run_java(["sm2-encrypt", msg, SM2_PUB])
    if ok_j:
        # C++ 解密
        ct_input = json.dumps({"ciphertext_hex": java_ct})
        keys_file = write_temp("sm2_dec_keys.json", json.dumps(KEYS_FOR_ENC))
        ct_file = write_temp("sm2_dec_input.json", ct_input)
        ok_c, cout, cerr = run_cpp(["decrypt", ct_file, keys_file, str(TEMP_DIR / "sm2_dec_out.json")])
        if ok_c:
            dec = read_temp_json("sm2_dec_out.json")
            cpp_pt = dec.get("plaintext", "")
            if cpp_pt == msg:
                record_result("SM2", "encrypt/decrypt", "Java→C++", "PASS",
                              f"msg={short}")
            else:
                record_result("SM2", "encrypt/decrypt", "Java→C++", "FAIL",
                              f"msg={short}, mismatch: got '{cpp_pt[:30]}'")
        else:
            record_result("SM2", "encrypt/decrypt", "Java→C++", "FAIL",
                          f"msg={short}, C++ decrypt error: {cerr[:100]}")
    else:
        record_result("SM2", "encrypt/decrypt", "Java→C++", "FAIL",
                      f"msg={short}, Java encrypt error: {java_ct[:100]}")

    # ---- Test: C++ Encrypt → Java Decrypt ----
    pt_file = write_temp("sm2_enc_pt.txt", msg)
    keys_file = write_temp("sm2_enc_keys.json", json.dumps(KEYS_FOR_ENC))
    ok_c, cout, cerr = run_cpp(["encrypt", pt_file, keys_file, str(TEMP_DIR / "sm2_enc_out.json")])
    if ok_c:
        enc_out = read_temp_json("sm2_enc_out.json")
        cpp_ct = enc_out.get("ciphertext_hex", "")
        ok_j, java_pt = run_java(["sm2-decrypt", cpp_ct, SM2_PRV])
        if ok_j and java_pt == msg:
            record_result("SM2", "encrypt/decrypt", "C++→Java", "PASS",
                          f"msg={short}")
        else:
            record_result("SM2", "encrypt/decrypt", "C++→Java", "FAIL",
                          f"msg={short}, mismatch: got '{java_pt[:30] if ok_j else java_ct[:30]}'")
    else:
        record_result("SM2", "encrypt/decrypt", "C++→Java", "FAIL",
                      f"msg={short}, C++ encrypt error: {cerr[:100]}")

# ============================================================
# 阶段3: SM2 签名/验签 双向
# ============================================================
print("\n" + "=" * 60)
print("Phase 3: SM2 Sign/Verify Bidirectional")
print("=" * 60)

for msg in TEST_MESSAGES:
    short = msg[:30].replace('\n', '\\n')

    # ---- Test: Java Sign → C++ Verify ----
    ok_j, java_sig = run_java(["sm2-sign", msg, SM2_PRV])
    if ok_j:
        verify_input = json.dumps({"content": msg, "signature_hex": java_sig})
        keys_file = write_temp("sm2_ver_keys.json", json.dumps(KEYS_FOR_SIGN))
        ver_file = write_temp("sm2_ver_input.json", verify_input)
        ok_c, cout, cerr = run_cpp(["verify", ver_file, keys_file, str(TEMP_DIR / "sm2_ver_out.json")])
        if ok_c:
            ver_out = read_temp_json("sm2_ver_out.json")
            if ver_out.get("verify_result") == True:
                record_result("SM2", "sign/verify", "Java→C++", "PASS",
                              f"msg={short}")
            else:
                record_result("SM2", "sign/verify", "Java→C++", "FAIL",
                              f"msg={short}, C++ verify returned false")
        else:
            record_result("SM2", "sign/verify", "Java→C++", "FAIL",
                          f"msg={short}, C++ verify error: {cerr[:100]}")
    else:
        record_result("SM2", "sign/verify", "Java→C++", "FAIL",
                      f"msg={short}, Java sign error: {java_sig[:100]}")

    # ---- Test: C++ Sign → Java Verify ----
    pt_file = write_temp("sm2_sign_pt.txt", msg)
    keys_file = write_temp("sm2_sign_keys.json", json.dumps(KEYS_FOR_SIGN))
    ok_c, cout, cerr = run_cpp(["sign", pt_file, keys_file, str(TEMP_DIR / "sm2_sign_out.json")])
    if ok_c:
        sign_out = read_temp_json("sm2_sign_out.json")
        cpp_sig = sign_out.get("signature_hex", "")
        ok_j, java_ver = run_java(["sm2-verify", msg, cpp_sig, SM2_PUB])
        if ok_j and java_ver.strip().lower() == "true":
            record_result("SM2", "sign/verify", "C++→Java", "PASS",
                          f"msg={short}")
        else:
            record_result("SM2", "sign/verify", "C++→Java", "FAIL",
                          f"msg={short}, Java verify returned: {java_ver[:50]}")
    else:
        record_result("SM2", "sign/verify", "C++→Java", "FAIL",
                      f"msg={short}, C++ sign error: {cerr[:100]}")

# ============================================================
# 阶段4: SM2 加密+签名 / 验签+解密 双向
# ============================================================
print("\n" + "=" * 60)
print("Phase 4: SM2 EncryptSign / VerifyDecrypt Bidirectional")
print("=" * 60)

for msg in TEST_MESSAGES:
    short = msg[:30].replace('\n', '\\n')

    # ---- Test: Java encrypt+sign → C++ verify+decrypt ----
    ok_e, java_ct = run_java(["sm2-encrypt", msg, SM2_PUB])
    ok_s, java_sig = run_java(["sm2-sign", java_ct if ok_e else msg, SM2_PRV])
    if ok_e and ok_s:
        # C++ verify_decrypt needs: input_json with {ciphertext_hex, signature_hex}
        # and keys_json with {signature_public_key, encryption_private_key}
        vd_input = json.dumps({"ciphertext_hex": java_ct, "signature_hex": java_sig})
        vd_keys = make_keys_json(enc_prv=SM2_PRV, sign_pub=SM2_PUB)
        vd_file = write_temp("sm2_vd_input.json", vd_input)
        vd_keys_file = write_temp("sm2_vd_keys.json", json.dumps(vd_keys))
        ok_c, cout, cerr = run_cpp(["verify_decrypt", vd_file, vd_keys_file, str(TEMP_DIR / "sm2_vd_out.json")])
        if ok_c:
            vd_out = read_temp_json("sm2_vd_out.json")
            if vd_out.get("verify_result") == True and vd_out.get("decrypted_text") == msg:
                record_result("SM2", "encrypt_sign/verify_decrypt", "Java→C++", "PASS",
                              f"msg={short}")
            else:
                record_result("SM2", "encrypt_sign/verify_decrypt", "Java→C++", "FAIL",
                              f"msg={short}, verify={vd_out.get('verify_result')}, text={vd_out.get('decrypted_text','')[:30]}")
        else:
            record_result("SM2", "encrypt_sign/verify_decrypt", "Java→C++", "FAIL",
                          f"msg={short}, C++ error: {cerr[:100]}")
    else:
        record_result("SM2", "encrypt_sign/verify_decrypt", "Java→C++", "FAIL",
                      f"msg={short}, Java encrypt/sign failed")

    # ---- Test: C++ encrypt_sign → Java verify+decrypt ----
    pt_file = write_temp("sm2_es_pt.txt", msg)
    es_keys = make_keys_json(enc_pub=SM2_PUB, sign_prv=SM2_PRV)
    es_keys_file = write_temp("sm2_es_keys.json", json.dumps(es_keys))
    ok_c, cout, cerr = run_cpp(["encrypt_sign", pt_file, es_keys_file, str(TEMP_DIR / "sm2_es_out.json")])
    if ok_c:
        es_out = read_temp_json("sm2_es_out.json")
        cpp_ct = es_out.get("ciphertext_hex", "")
        cpp_sig = es_out.get("signature_hex", "")
        # Java verify the signature on the ciphertext, then decrypt
        ok_v, java_ver = run_java(["sm2-verify", cpp_ct, cpp_sig, SM2_PUB])
        if ok_v and java_ver.strip().lower() == "true":
            ok_d, java_pt = run_java(["sm2-decrypt", cpp_ct, SM2_PRV])
            if ok_d and java_pt == msg:
                record_result("SM2", "encrypt_sign/verify_decrypt", "C++→Java", "PASS",
                              f"msg={short}")
            else:
                record_result("SM2", "encrypt_sign/verify_decrypt", "C++→Java", "FAIL",
                              f"msg={short}, decrypt mismatch: {java_pt[:30]}")
        else:
            record_result("SM2", "encrypt_sign/verify_decrypt", "C++→Java", "FAIL",
                          f"msg={short}, verify returned: {java_ver[:50]}")
    else:
        record_result("SM2", "encrypt_sign/verify_decrypt", "C++→Java", "FAIL",
                      f"msg={short}, C++ error: {cerr[:100]}")

# ============================================================
# 阶段5: SM3 摘要 双向比对
# ============================================================
print("\n" + "=" * 60)
print("Phase 5: SM3 Digest Bidirectional")
print("=" * 60)

for msg in TEST_MESSAGES:
    short = msg[:30].replace('\n', '\\n')

    ok_j, java_sm3 = run_java(["sm3-digest", msg])
    pt_file = write_temp("sm3_pt.txt", msg)
    ok_c, cout, cerr = run_cpp(["sm3_digest", pt_file, str(TEMP_DIR / "sm3_out.json")])
    if ok_c:
        sm3_out = read_temp_json("sm3_out.json")
        cpp_sm3 = sm3_out.get("digest_hex", "")
        if java_sm3 == cpp_sm3:
            record_result("SM3", "digest", "Java↔C++", "PASS",
                          f"msg={short}, digest={java_sm3[:16]}...")
        else:
            record_result("SM3", "digest", "Java↔C++", "FAIL",
                          f"msg={short}, JAVA={java_sm3[:16]}..., CPP={cpp_sm3[:16]}...")
    else:
        record_result("SM3", "digest", "Java↔C++", "FAIL",
                      f"msg={short}, C++ error: {cerr[:100]}")

# ============================================================
# 阶段6: HMAC-SM3 双向比对
# ============================================================
print("\n" + "=" * 60)
print("Phase 6: HMAC-SM3 Bidirectional")
print("=" * 60)

for msg in TEST_MESSAGES:
    short = msg[:30].replace('\n', '\\n')

    ok_j, java_hmac = run_java(["sm3-hmac", HMAC_KEY_HEX, msg])
    hmac_input = json.dumps({"hmac_key_hex": HMAC_KEY_HEX, "data": msg})
    hmac_file = write_temp("hmac_input.json", hmac_input)
    ok_c, cout, cerr = run_cpp(["sm3_hmac", hmac_file, str(TEMP_DIR / "hmac_out.json")])
    if ok_c:
        hmac_out = read_temp_json("hmac_out.json")
        cpp_hmac = hmac_out.get("hmac_hex", "")
        if java_hmac == cpp_hmac:
            record_result("HMAC-SM3", "hmac", "Java↔C++", "PASS",
                          f"msg={short}, hmac={java_hmac[:16]}...")
        else:
            record_result("HMAC-SM3", "hmac", "Java↔C++", "FAIL",
                          f"msg={short}, JAVA={java_hmac[:16]}..., CPP={cpp_hmac[:16]}...")
    else:
        record_result("HMAC-SM3", "hmac", "Java↔C++", "FAIL",
                      f"msg={short}, C++ error: {cerr[:100]}")

# ============================================================
# 阶段7: SM4 加密/解密 双向
# ============================================================
print("\n" + "=" * 60)
print("Phase 7: SM4 Encrypt/Decrypt Bidirectional")
print("=" * 60)

for msg in TEST_MESSAGES:
    short = msg[:30].replace('\n', '\\n')

    # ---- Test: Java Encrypt → C++ Decrypt ----
    ok_j, java_sm4_ct = run_java(["sm4-encrypt", msg, FIXED_SM4_KEY])
    if ok_j:
        sm4_dec_input = json.dumps({"sm4_key_hex": FIXED_SM4_KEY, "ciphertext_hex": java_sm4_ct})
        sm4_in_file = write_temp("sm4_dec_input.json", sm4_dec_input)
        ok_c, cout, cerr = run_cpp(["sm4_decrypt", sm4_in_file, str(TEMP_DIR / "sm4_dec_out.json")])
        if ok_c:
            dec_out = read_temp_json("sm4_dec_out.json")
            cpp_pt = dec_out.get("plaintext", "")
            if cpp_pt == msg:
                record_result("SM4", "encrypt/decrypt", "Java→C++", "PASS",
                              f"msg={short}")
            else:
                record_result("SM4", "encrypt/decrypt", "Java→C++", "FAIL",
                              f"msg={short}, mismatch: got '{cpp_pt[:30]}'")
        else:
            record_result("SM4", "encrypt/decrypt", "Java→C++", "FAIL",
                          f"msg={short}, C++ error: {cerr[:100]}")
    else:
        record_result("SM4", "encrypt/decrypt", "Java→C++", "FAIL",
                      f"msg={short}, Java encrypt error: {java_sm4_ct[:100]}")

    # ---- Test: C++ Encrypt → Java Decrypt ----
    sm4_enc_input = json.dumps({"sm4_key_hex": FIXED_SM4_KEY, "plaintext": msg})
    sm4_enc_file = write_temp("sm4_enc_input.json", sm4_enc_input)
    ok_c, cout, cerr = run_cpp(["sm4_encrypt", sm4_enc_file, str(TEMP_DIR / "sm4_enc_out.json")])
    if ok_c:
        enc_out = read_temp_json("sm4_enc_out.json")
        cpp_sm4_ct = enc_out.get("ciphertext_hex", "")
        ok_j, java_pt = run_java(["sm4-decrypt", cpp_sm4_ct, FIXED_SM4_KEY])
        if ok_j and java_pt == msg:
            record_result("SM4", "encrypt/decrypt", "C++→Java", "PASS",
                          f"msg={short}")
        else:
            record_result("SM4", "encrypt/decrypt", "C++→Java", "FAIL",
                          f"msg={short}, mismatch: got '{java_pt[:30] if ok_j else cpp_sm4_ct[:30]}'")
    else:
        record_result("SM4", "encrypt/decrypt", "C++→Java", "FAIL",
                      f"msg={short}, C++ error: {cerr[:100]}")

# ============================================================
# 结果汇总
# ============================================================
total = pass_count + fail_count
print("\n" + "=" * 60)
print("TEST SUMMARY")
print("=" * 60)
print(f"  Total:  {total}")
print(f"  Passed: {pass_count}")
print(f"  Failed: {fail_count}")
print(f"  Rate:   {pass_count / total * 100:.1f}%" if total > 0 else "  Rate: N/A")

# 保存结果
RESULT_DIR.mkdir(parents=True, exist_ok=True)
now = datetime.now().strftime("%Y%m%d_%H%M%S")
result_file = RESULT_DIR / f"java_cpp_interop_results_{now}.json"
with open(result_file, 'w', encoding='utf-8') as f:
    json.dump({
        "test_time": datetime.now().isoformat(),
        "total": total,
        "passed": pass_count,
        "failed": fail_count,
        "rate": f"{pass_count / total * 100:.1f}%" if total > 0 else "N/A",
        "sm2_public_key": SM2_PUB,
        "results": results
    }, f, indent=2, ensure_ascii=False)

print(f"\nResults saved to: {result_file}")
sys.exit(0 if fail_count == 0 else 1)
