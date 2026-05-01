#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Debug Java output"""

import sys
import os
sys.path.insert(0, '.')

import importlib.util
spec = importlib.util.spec_from_file_location('jet', 'testcase/java_encrypt_test.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

# 手动执行 Java 命令
os.makedirs(m.TEST_CLASS_DIR, exist_ok=True)
java_class_file = os.path.join(m.TEST_CLASS_DIR, 'SM2KeyGenTest.java')
java_code = '''package testcase;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.SerialKeyPair;
public class SM2KeyGenTest {
    public static void main(String[] args) {
        try {
            SerialKeyPair keyPair = SM2Util.generateKeyPairHex();
            System.out.println(keyPair.getPublicKey());
            System.out.println(keyPair.getPrivateKey());
        } catch (Exception e) {
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
'''
with open(java_class_file, 'w', encoding='utf-8') as f:
    f.write(java_code)

with open(m.CLASSPATH_FILE, 'r', encoding='utf-8') as f:
    dependency_classpath = f.read().strip()

full_classpath = f'{m.TEST_CLASS_DIR};{m.JAR_PATH};{dependency_classpath}'
print('Classpath:', full_classpath[:100])

compile_result = subprocess.run(
    [m.JAVAC_EXECUTABLE, '-d', m.TEST_CLASS_DIR, '-cp', f'{m.JAR_PATH};{dependency_classpath}', java_class_file],
    capture_output=True, text=True
)
print('Compile returncode:', compile_result.returncode)

run_result = subprocess.run(
    f'"{m.JAVA_EXECUTABLE}" -cp "{full_classpath}" testcase.SM2KeyGenTest',
    capture_output=True, text=True, shell=True
)
print('Run returncode:', run_result.returncode)
print('Stdout[:500]:', repr(run_result.stdout[:500]))
print('Stderr[:200]:', repr(run_result.stderr[:200]))

# 测试正则表达式
import re
output = run_result.stdout.strip()
pub_match = re.search(r'publicKeyStr:([0-9a-fA-F]+)', output, re.IGNORECASE)
print('pub_match:', pub_match)
if pub_match:
    print('group(1):', pub_match.group(1)[:50])