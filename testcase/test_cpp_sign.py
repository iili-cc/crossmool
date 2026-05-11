"""
Test C++ encrypt then decrypt via interoperability_test.exe commands
"""
import subprocess
import json
import os

exe = r"G:\workspaces\git\corssmool\crossmool\cpp\crossmool\build\bin\Release\interoperability_test.exe"
temp = r"G:\workspaces\git\corssmool\crossmool\testcase\.cpp_temp"
os.makedirs(temp, exist_ok=True)

input_file = os.path.join(temp, "input.txt")
keys_file = os.path.join(temp, "keys.json")
enc_output = os.path.join(temp, "enc_output.json")
dec_output = os.path.join(temp, "dec_output.json")

with open(input_file, 'w') as f:
    f.write("Hello Test")

keys = {
    "encryption_public_key": {"hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004f4b485c673890b91acb987244700fc6777a81936dec7df663fe8b7402c53da2f85c30ea6138f9083dac51fe95320e540e6b1fdf2972582fe88d9ca2310de3dc4"},
    "signature_private_key": {"hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b020101042016a43700f756d0b0745693fdcf9ef53c8c9dc0c87183ab371c6d7b12882ee87aa14403420004f4b485c673890b91acb987244700fc6777a81936dec7df663fe8b7402c53da2f85c30ea6138f9083dac51fe95320e540e6b1fdf2972582fe88d9ca2310de3dc4"}
}
with open(keys_file, 'w') as f:
    json.dump(keys, f)

# Test 1: sign (simpler, no key format issues)
sign_output = os.path.join(temp, "sign_output.json")
cmd = [exe, "sign", input_file, keys_file, sign_output]
result = subprocess.run(cmd, capture_output=True, timeout=10, text=True)
print(f"=== SIGN ===")
print(f"stdout: {result.stdout.strip()}")
print(f"stderr: {result.stderr.strip()}")
print(f"returncode: {result.returncode}")
if os.path.exists(sign_output):
    with open(sign_output) as f:
        print(f"output: {f.read()}")

# Test 2: verify
verify_input = os.path.join(temp, "verify_input.json")
if os.path.exists(sign_output):
    with open(sign_output) as f:
        sig_data = json.load(f)
    verify_input_data = {
        "content": "Hello Test",
        "signature_hex": sig_data.get("signature_hex", "")
    }
    with open(verify_input, 'w') as f:
        json.dump(verify_input_data, f)
    
    verify_output = os.path.join(temp, "verify_output.json")
    cmd = [exe, "verify", verify_input, keys_file, verify_output]
    result = subprocess.run(cmd, capture_output=True, timeout=10, text=True)
    print(f"\n=== VERIFY ===")
    print(f"stdout: {result.stdout.strip()}")
    print(f"stderr: {result.stderr.strip()}")
    if os.path.exists(verify_output):
        with open(verify_output) as f:
            print(f"output: {f.read()}")
