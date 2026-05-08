#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
重新生成 Java 测试数据（用当前 keys.json 中的密钥）
"""
import subprocess
import json
import os
import shutil

REPO_ROOT = r"G:\workspaces\git\corssmool\crossmool"
JAVA_EXEC = r"H:\Programs\Java\jdk-21.0.1+12\bin\java.exe"
JAVAC_EXEC = r"H:\Programs\Java\jdk-21.0.1+12\bin\javac.exe"
JAR_PATH = os.path.join(REPO_ROOT, r"java\crossmool\target\crossmool-1.1.0.jar")
CLASSPATH_FILE = os.path.join(REPO_ROOT, r"java\crossmool\classpath.txt")
TEST_CLASS_DIR = os.path.join(REPO_ROOT, r"testcase\java_test_classes")
KEYS_FILE = os.path.join(REPO_ROOT, r"testcase\keys\java\keys.json")
TEST_DATA_FILE = os.path.join(REPO_ROOT, r"testcase\test_data.json")
OUTPUT_DIR = os.path.join(REPO_ROOT, r"testcase\results\java_encrypt")

# 读取 classpath
with open(CLASSPATH_FILE, encoding='utf-8') as f:
    dep_classpath = f.read().strip()

full_classpath = f"{JAR_PATH};{TEST_CLASS_DIR};{dep_classpath}"

# 读取密钥
with open(KEYS_FILE, encoding='utf-8') as f:
    keys = json.load(f)

enc_pub_hex = keys["encryption_public_key"]["hex"]
sign_priv_hex = keys["signature_private_key"]["hex"]

print(f"加密公钥 (前40): {enc_pub_hex[:40]}...")
print(f"签名私钥 (前40): {sign_priv_hex[:40]}...")

# 读取测试数据
with open(TEST_DATA_FILE, encoding='utf-8') as f:
    test_data = json.load(f)

test_cases = test_data["test_cases"]
print(f"\n找到 {len(test_cases)} 个测试用例")

# 确保输出目录存在
os.makedirs(OUTPUT_DIR, exist_ok=True)

success = 0
fail = 0

for tc in test_cases:
    tid = tc["id"]
    tname = tc["name"]
    plaintext = tc["plaintext"]
    
    print(f"\n[{tid}] {tname}")
    print(f"  明文: {repr(plaintext[:40])}")
    
    # 调用 Java SM2InteropTest 进行加密签名
    cmd = [JAVA_EXEC, "-cp", full_classpath, "testcase.SM2InteropTest",
           plaintext, enc_pub_hex, sign_priv_hex]
    
    result = subprocess.run(cmd, capture_output=True, timeout=30, cwd=REPO_ROOT)
    stdout = result.stdout.decode('utf-8', errors='replace').strip()
    stderr = result.stderr.decode('utf-8', errors='replace').strip()
    
    if result.returncode != 0 or not stdout:
        print(f"  [FAIL] 运行失败: rc={result.returncode}, stderr={stderr[:100]}")
        fail += 1
        continue
    
    parts = stdout.split('\t')
    if len(parts) != 2:
        print(f"  [FAIL] 输出格式异常: {stdout[:100]}")
        fail += 1
        continue
    
    ct_hex, sig_hex = parts
    print(f"  密文 (前40): {ct_hex[:40]}...")
    print(f"  签名 (前40): {sig_hex[:40]}...")
    
    # 保存结果
    safe_name = tname.replace(" ", "_")
    out_file = os.path.join(OUTPUT_DIR, f"test_{tid}_{safe_name}.json")
    result_data = {
        "test_case_id": tid,
        "test_case_name": tname,
        "plaintext": plaintext,
        "ciphertext_hex": ct_hex,
        "signature_hex": sig_hex
    }
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(result_data, f, indent=2, ensure_ascii=False)
    print(f"  [OK] 保存到 {os.path.basename(out_file)}")
    success += 1

print(f"\n完成! 成功 {success}/{success+fail}")
