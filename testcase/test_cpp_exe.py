"""
Quick test: verify C++ interoperability_test.exe works via encrypt command
"""
import subprocess
import json
import os

exe = r"G:\workspaces\git\corssmool\crossmool\cpp\crossmool\build\bin\Release\interoperability_test.exe"
temp = r"G:\workspaces\git\corssmool\crossmool\testcase\.cpp_temp"
os.makedirs(temp, exist_ok=True)

# Test 1: encrypt only
input_file = os.path.join(temp, "input.txt")
keys_file = os.path.join(temp, "keys.json")
output_file = os.path.join(temp, "output.json")

with open(input_file, 'w') as f:
    f.write("Hello Test")

keys = {
    "encryption_public_key": {"hex": "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"},
    "signature_private_key": {"hex": "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4"}
}
with open(keys_file, 'w') as f:
    json.dump(keys, f)

# Test encrypt
cmd = [exe, "encrypt", input_file, keys_file, output_file]
print(f"Running: {' '.join(cmd)}")
result = subprocess.run(cmd, capture_output=True, timeout=10, text=True)
print(f"stdout: {result.stdout}")
print(f"stderr: {result.stderr}")
print(f"returncode: {result.returncode}")

if os.path.exists(output_file):
    with open(output_file) as f:
        print(f"output: {f.read()}")
else:
    print("No output file generated")

# Cleanup
for f in [input_file, keys_file, output_file]:
    if os.path.exists(f):
        os.remove(f)
