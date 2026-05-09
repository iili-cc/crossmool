#!/usr/bin/env python3
"""Compile C interop test program"""
import subprocess
import os

SRC_DIR = r"G:\workspaces\git\corssmool\crossmool"
TEST_DIR = os.path.join(SRC_DIR, "testcase")
C_SRC = os.path.join(SRC_DIR, r"c\crossmool\src")
C_INC = os.path.join(SRC_DIR, r"c\crossmool\include")
GMSSL_DIR = os.path.join(SRC_DIR, r"c\crossmool\GmSSL\build")

os.chdir(TEST_DIR)

# Find vcvars64.bat
vs_paths = [
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    r"H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
]

for vs_path in vs_paths:
    if os.path.exists(vs_path):
        # Run vcvars64.bat and capture environment
        result = subprocess.run(
            f'cmd.exe /c "call "{vs_path}" && set"',
            capture_output=True,
            text=True
        )
        env_vars = {}
        for line in result.stdout.split('\n'):
            if '=' in line:
                key, val = line.split('=', 1)
                env_vars[key] = val
        
        # Merge with current environment
        os.environ.update(env_vars)
        print(f"Using VS: {vs_path}")
        break
else:
    print("ERROR: Visual Studio not found!")
    exit(1)

# Compile - use GmSSL source include path (contains gmssl/ subdir)
GMSSL_INCLUDE = os.path.join(SRC_DIR, r"c\crossmool\GmSSL\include")
GMSSL_LIB_DIR = os.path.join(SRC_DIR, r"c\crossmool\GmSSL\build_msvc\bin")
cmd = [
    "cl", "/MD", "/utf-8",
    f"/I{C_INC}",
    f"/I{GMSSL_INCLUDE}",
    "test_java_c_interop_sm.c",
    os.path.join(C_SRC, "sm2.c"),
    os.path.join(C_SRC, "sm3.c"),
    os.path.join(C_SRC, "sm4.c"),
    os.path.join(C_SRC, "util_hex.c"),
    os.path.join(C_SRC, "util_base64.c"),
    os.path.join(C_SRC, "util_string.c"),
    os.path.join(C_SRC, "error.c"),
    "/link",
    f"/LIBPATH:{GMSSL_LIB_DIR}",
    "gmssl.lib",
    "/OUT:test_java_c_interop_sm.exe"
]

print(f"Compiling: {' '.join(cmd)}")
print("=" * 80)

result = subprocess.run(cmd, capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)

print("=" * 80)
print(f"Exit code: {result.returncode}")

if result.returncode == 0:
    print("[OK] Compilation successful!")
    if os.path.exists("test_java_c_interop_sm.exe"):
        print(f"[OK] EXE created: {os.path.abspath('test_java_c_interop_sm.exe')}")
else:
    print("[ERROR] Compilation failed!")