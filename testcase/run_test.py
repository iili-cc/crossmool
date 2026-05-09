#!/usr/bin/env python3
"""Run C interop test with Java-generated test data"""
import json
import subprocess
import os

TEST_DIR = r"G:\workspaces\git\corssmool\crossmool\testcase"
os.chdir(TEST_DIR)

# Add GmSSL DLL to PATH
GMSSL_DLL_DIR = r"G:\workspaces\git\corssmool\crossmool\c\crossmool\GmSSL\build_msvc\bin"
os.environ["PATH"] = GMSSL_DLL_DIR + os.pathsep + os.environ.get("PATH", "")

# Load test data
with open("test_data.json", "r") as f:
    data = json.load(f)

print("Loading test data from test_data.json...")
print("=" * 80)

# Extract values
sm2_priv = data["sm2_private_key"]
sm2_pub = data["sm2_public_key"]
sm4_key = data["sm4_key_hex"]
sm2_cipher = data["sm2_ciphertext"]
sm2_sig = data["sm2_signature"]
sm3_digest = data["sm3_digest"]
hmac_sm3 = data["hmac_sm3"]
sm4_cipher = data["sm4_ciphertext"]
test_msg = data["test_message"]

print(f"Test Message: {test_msg}")
print(f"SM2 Public:   {sm2_pub[:64]}...")
print(f"SM2 Private:  {sm2_priv[:64]}...")
print(f"SM4 Key:      {sm4_key}")
print(f"SM2 Cipher:   {sm2_cipher[:64]}...")
print(f"SM2 Sign:     {sm2_sig[:64]}...")
print(f"SM3 Digest:   {sm3_digest}")
print(f"HMAC-SM3:     {hmac_sm3}")
print(f"SM4 Cipher:   {sm4_cipher[:64]}...")
print("=" * 80)

# Run C test
cmd = [
    "test_java_c_interop_sm.exe",
    sm2_priv,
    sm2_pub,
    sm4_key,
    sm2_cipher,
    sm2_sig,
    sm3_digest,
    hmac_sm3,
    sm4_cipher
]

print(f"Running: {' '.join(cmd[:4])} ...")
print("=" * 80)

result = subprocess.run(cmd, capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)

print("=" * 80)
print(f"Exit code: {result.returncode}")

if result.returncode == 0:
    print("[OK] All C tests passed!")
else:
    print("[ERROR] Some C tests failed!")