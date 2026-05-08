#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os

print(f"Python executable: {sys.executable}")
print(f"Current dir: {os.getcwd()}")
print(f"Script exists: {os.path.exists('testcase/java_to_c_verify_test.py')}")

# 尝试导入并运行
sys.path.insert(0, 'testcase')
import java_to_c_verify_test

print("Running main()...")
result = java_to_c_verify_test.main()
print(f"Exit code: {result}")