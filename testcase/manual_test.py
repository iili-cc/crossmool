#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os

# 切换到项目根目录
os.chdir(r'g:\workspaces\git\corssmool\crossmool')

print(f"Current directory: {os.getcwd()}")
print(f"Python: {sys.executable}")

# 直接运行测试脚本
exec(open('testcase/java_to_c_verify_test.py', encoding='utf-8').read())