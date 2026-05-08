#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""简单的验签测试脚本，用于调试"""

import os
import subprocess
import tempfile
import shutil

# 配置
C_INCLUDE_PATH = r"c/crossmool/include"
C_DLL_PATH = r"c/crossmool/build_msvc/Release"
VSDEVCMD_PATH = r"H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"

print(f"Checking paths...")
print(f"  C_INCLUDE_PATH exists: {os.path.exists(C_INCLUDE_PATH)}")
print(f"  C_DLL_PATH exists: {os.path.exists(C_DLL_PATH)}")
print(f"  VSDEVCMD_PATH exists: {os.path.exists(VSDEVCMD_PATH)}")

# 获取 MSVC x64 环境
print(f"\nGetting MSVC x64 environment...")
cmd = f'cmd /c "call "{VSDEVCMD_PATH}" -host_arch=amd64 -arch=amd64 && set"'

result = subprocess.run(
    cmd,
    shell=True,
    capture_output=True,
    encoding='gbk',
    errors='ignore',
    timeout=60
)

print(f"VsDevCmd returncode: {result.returncode}")

if result.returncode == 0:
    # 解析环境变量
    env_vars = os.environ.copy()
    for line in result.stdout.split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            env_vars[key.strip()] = value.strip()
    
    platform = env_vars.get('PLATFORM', 'NOT SET')
    print(f"  PLATFORM: {platform}")
    
    # 创建简单的测试 C 文件
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_c_file = os.path.join(temp_dir, "test.c")
        temp_exe_file = os.path.join(temp_dir, "test.exe")
        
        with open(temp_c_file, 'w', encoding='utf-8') as f:
            f.write('#include <stdio.h>\nint main() { printf("Hello from x64!\\n"); return 0; }\n')
        
        # 编译
        compile_cmd = f'cl.exe "{temp_c_file}" /Fe"{temp_exe_file}"'
        print(f"\nCompiling: {compile_cmd}")
        
        compile_result = subprocess.run(
            compile_cmd,
            shell=True,
            capture_output=True,
            encoding='gbk',
            errors='ignore',
            env=env_vars
        )
        
        print(f"Compile returncode: {compile_result.returncode}")
        print(f"Compile stdout: {compile_result.stdout[:500] if compile_result.stdout else 'None'}")
        print(f"Compile stderr: {compile_result.stderr[:500] if compile_result.stderr else 'None'}")
        
        if compile_result.returncode == 0:
            # 运行
            run_result = subprocess.run(
                temp_exe_file,
                capture_output=True,
                encoding='gbk',
                errors='ignore'
            )
            print(f"\nRun output: {run_result.stdout}")
else:
    print(f"VsDevCmd failed: {result.stderr[:500] if result.stderr else 'Unknown error'}")