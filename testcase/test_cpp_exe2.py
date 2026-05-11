"""
Debug: test C++ interoperability_test.exe with verbose key extraction
"""
import subprocess
import json
import os

exe = r"G:\workspaces\git\corssmool\crossmool\cpp\crossmool\build\bin\Release\interoperability_test.exe"
temp = r"G:\workspaces\git\corssmool\crossmool\testcase\.cpp_temp"
os.makedirs(temp, exist_ok=True)

input_file = os.path.join(temp, "input.txt")
keys_file = os.path.join(temp, "keys.json")
output_file = os.path.join(temp, "output.json")

with open(input_file, 'w') as f:
    f.write("Hello Test")

# Use C++ keys format (simpler)
cpp_keys = {
    "encryption_public_key": {
        "hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004f4b485c673890b91acb987244700fc6777a81936dec7df663fe8b7402c53da2f85c30ea6138f9083dac51fe95320e540e6b1fdf2972582fe88d9ca2310de3dc4",
        "base64": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAETNLP5u/8+dGPLoXS+pvwbFL9Smd+zcWAkJhvmi/uypRY8ubkthkbTRy/3TfrbmaA9fG4dfy2Ba6G1sKYR+0Acg=="
    },
    "signature_private_key": {
        "hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b020101042016a43700f756d0b0745693fdcf9ef53c8c9dc0c87183ab371c6d7b12882ee87aa14403420004f4b485c673890b91acb987244700fc6777a81936dec7df663fe8b7402c53da2f85c30ea6138f9083dac51fe95320e540e6b1fdf2972582fe88d9ca2310de3dc4",
        "base64": "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgiU3x/fMfkgKKOShboRSrLWYsz02MrjLqeIhVXkmpNXyhRANCAARM0s/m7/z50Y8uhdL6m/BsUv1KZ37NxYCQmG+aL+7KlFjy5uS2GRtNHL/dN+tuZoD18bh1/LYFrobWwphH7QBy"
    }
}
with open(keys_file, 'w') as f:
    json.dump(cpp_keys, f, indent=2)

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
