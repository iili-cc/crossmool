#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最小化测试脚本"""
import os
import sys
from datetime import datetime

# 切换到项目根目录
os.chdir(r'g:\workspaces\git\corssmool\crossmool')

log_file = "java_interop_test_20260507.log"

print(f"Current directory: {os.getcwd()}")
print(f"Log file: {log_file}")

# 写入日志
with open(log_file, 'w', encoding='utf-8') as f:
    f.write(f"[{datetime.now()}] Test started\n")

print(f"Log file created: {os.path.exists(log_file)}")

# 检查密钥文件
keys_file = "testcase/keys/java/keys.json"
if os.path.exists(keys_file):
    import json
    with open(keys_file, 'r', encoding='utf-8') as f:
        keys = json.load(f)
    print(f"Keys loaded: {list(keys.keys())}")
else:
    print(f"Keys file not found: {keys_file}")

# 检查加密结果目录
import glob
encrypt_files = glob.glob("testcase/results/java_encrypt/test_*.json")
print(f"Found {len(encrypt_files)} test files")

print("Done!")