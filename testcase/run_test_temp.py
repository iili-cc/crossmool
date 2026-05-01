#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""临时测试脚本，用于捕获完整输出"""

import subprocess
import sys

script_path = "g:/workspaces/git/corssmool/crossmool/testcase/java_encrypt_sign.py"
python_path = "H:/Programs/Python3/python.exe"

result = subprocess.run(
    [python_path, script_path],
    capture_output=True,
    text=True,
    cwd="g:/workspaces/git/corssmool/crossmool"
)

# 输出到文件
with open("g:/workspaces/git/corssmool/crossmool/testcase/test_output.log", "w", encoding="utf-8") as f:
    f.write("=" * 60 + "\n")
    f.write("STDOUT:\n")
    f.write("=" * 60 + "\n")
    f.write(result.stdout)
    f.write("=" * 60 + "\n")
    f.write("STDERR:\n")
    f.write("=" * 60 + "\n")
    f.write(result.stderr)
    f.write("=" * 60 + "\n")
    f.write(f"RETURN CODE: {result.returncode}\n")
    f.write("=" * 60 + "\n")

print("输出已写入 testcase/test_output.log")
print(f"返回码：{result.returncode}")
