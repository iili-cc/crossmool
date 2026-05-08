#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import subprocess

# 检查 VsDevCmd.bat 路径
paths = [
    r"H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat",
    r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat",
]

print("Checking VsDevCmd.bat paths:")
found_path = None
for p in paths:
    exists = os.path.exists(p)
    print(f"  {'[OK]' if exists else '[NOT FOUND]'} {p}")
    if exists:
        found_path = p

if found_path:
    print(f"\nFound VsDevCmd.bat: {found_path}")
    
    # 测试 -arch=amd64 参数
    print("\nTesting: call VsDevCmd.bat -arch=amd64")
    test_cmd = f'cmd /c "call "{found_path}" -arch=amd64 && set | findstr PLATFORM"'
    result = subprocess.run(test_cmd, shell=True, capture_output=True, text=True, encoding='gbk')
    print(f"stdout: {result.stdout}")
    print(f"stderr: {result.stderr}")
    print(f"returncode: {result.returncode}")
else:
    print("\nNo VsDevCmd.bat found!")