#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
运行 Java SM2DebugZ 类，打印 Z 值和哈希
"""
import subprocess
import os
import shutil

REPO_ROOT = r"G:\workspaces\git\corssmool\crossmool"
JAVA_EXEC = r"H:\Programs\Java\jdk-21.0.1+12\bin\java.exe"
JAVAC_EXEC = r"H:\Programs\Java\jdk-21.0.1+12\bin\javac.exe"
JAR_PATH = os.path.join(REPO_ROOT, r"java\crossmool\target\crossmool-1.1.0.jar")
CLASSPATH_FILE = os.path.join(REPO_ROOT, r"java\crossmool\classpath.txt")
TEST_CLASS_DIR = os.path.join(REPO_ROOT, r"testcase\java_test_classes")

# 读取 classpath
with open(CLASSPATH_FILE, encoding='utf-8') as f:
    dep_classpath = f.read().strip()

# 构建完整 classpath
full_classpath = f"{JAR_PATH};{TEST_CLASS_DIR};{dep_classpath}"

# 编译 SM2DebugZ.java
java_file = os.path.join(TEST_CLASS_DIR, "SM2DebugZ.java")
print("编译 SM2DebugZ.java...")
result = subprocess.run(
    [JAVAC_EXEC, "-cp", full_classpath, "-d", TEST_CLASS_DIR, java_file],
    capture_output=True, timeout=30
)
stdout = result.stdout.decode('utf-8', errors='replace')
stderr = result.stderr.decode('utf-8', errors='replace')
print(f"编译结果: rc={result.returncode}")
if stdout: print("STDOUT:", stdout)
if stderr: print("STDERR:", stderr)

if result.returncode != 0:
    print("编译失败!")
    exit(1)

# 运行 SM2DebugZ
print("\n运行 SM2DebugZ...")
result2 = subprocess.run(
    [JAVA_EXEC, "-cp", full_classpath, "testcase.SM2DebugZ"],
    capture_output=True, timeout=30, cwd=REPO_ROOT
)
stdout2 = result2.stdout.decode('utf-8', errors='replace')
stderr2 = result2.stderr.decode('utf-8', errors='replace')
print("STDOUT:\n", stdout2)
if stderr2:
    print("STDERR:\n", stderr2)
