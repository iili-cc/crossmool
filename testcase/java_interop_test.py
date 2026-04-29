#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java SM2 加密和签名互操作性测试脚本

功能：
1. 读取 testcase/keys/java/keys.json 中的密钥
2. 读取 testcase/test_data.json 中的测试数据
3. 调用 Java 命令行工具执行加密和签名操作
4. 输出 Hex 格式的密文和签名到 testcase/results/java_encrypt 目录
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# 配置路径
JDK_HOME = r"H:\Programs\Java\jdk-21.0.1+12"
JAVA_EXECUTABLE = os.path.join(JDK_HOME, "bin", "java.exe")
JAR_PATH = "java/crossmool/target/crossmool-1.1.0.jar"
CLASSPATH_FILE = "java/crossmool/classpath.txt"
KEYS_FILE = "testcase/keys/java/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/java_encrypt"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_java_command(content, enc_public_key_hex, sign_private_key_hex):
    """
    运行 Java 命令执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 创建临时 Java 类来执行操作
    java_code = f'''
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

public class SM2TestRunner {{
    public static void main(String[] args) {{
        String content = "{content}";
        String encPublicKey = "{enc_public_key_hex}";
        String signPrivateKey = "{sign_private_key_hex}";
        
        try {{
            CiphertextSignaturePair result = SM2Util.encryptSign(content, encPublicKey, signPrivateKey, false);
            System.out.println(result.getCiphertext() + "\\t" + result.getSignature());
        }} catch (Exception e) {{
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }}
    }}
}}
'''
    # 写入临时 Java 文件
    temp_java_file = "SM2TestRunner.java"
    with open(temp_java_file, 'w', encoding='utf-8') as f:
        f.write(java_code)
    
    try:
        # 编译 Java 文件
        compile_cmd = [
            JAVA_EXECUTABLE,
            "-cp", JAR_PATH,
            "javac",
            "-cp", JAR_PATH,
            temp_java_file
        ]
        
        # 使用 javac 编译
        javac_path = os.path.join(JDK_HOME, "bin", "javac.exe")
        compile_result = subprocess.run(
            [javac_path, "-cp", JAR_PATH, temp_java_file],
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        
        if compile_result.returncode != 0:
            print(f"编译失败：{compile_result.stderr}")
            return None
        
        # 运行 Java 程序
        run_result = subprocess.run(
            [JAVA_EXECUTABLE, "-cp", f".:{JAR_PATH}", "SM2TestRunner"],
            capture_output=True,
            text=True
        )
        
        if run_result.returncode != 0:
            print(f"运行失败：{run_result.stderr}")
            return None
        
        # 解析输出
        output = run_result.stdout.strip()
        parts = output.split('\t')
        if len(parts) == 2:
            return {
                "ciphertext": parts[0],
                "signature": parts[1]
            }
        else:
            print(f"输出格式错误：{output}")
            return None
            
    finally:
        # 清理临时文件
        for f in [temp_java_file, "SM2TestRunner.class"]:
            if os.path.exists(f):
                os.remove(f)

def run_java_command_v2(content, enc_public_key_hex, sign_private_key_hex):
    """
    运行 Java 命令执行加密和签名 (v2 版本 - 使用独立的测试类)
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 创建测试类目录
    test_class_dir = "testcase/java_test_classes"
    os.makedirs(test_class_dir, exist_ok=True)
    
    # 创建 Java 测试类
    java_class_file = os.path.join(test_class_dir, "SM2InteropTest.java")
    
    # 转义内容中的特殊字符
    escaped_content = content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t').replace('\r', '\\r')
    
    java_code = f'''package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

public class SM2InteropTest {{
    public static void main(String[] args) {{
        if (args.length != 3) {{
            System.err.println("Usage: SM2InteropTest <content> <encPublicKey> <signPrivateKey>");
            System.exit(1);
        }}
        
        String content = args[0];
        String encPublicKey = args[1];
        String signPrivateKey = args[2];
        
        try {{
            CiphertextSignaturePair result = SM2Util.encryptSign(content, encPublicKey, signPrivateKey, false);
            System.out.println(result.getCiphertext() + "\\t" + result.getSignature());
        }} catch (Exception e) {{
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }}
    }}
}}
'''
    
    with open(java_class_file, 'w', encoding='utf-8') as f:
        f.write(java_code)
    
    try:
        # 读取 classpath 文件
        if not os.path.exists(CLASSPATH_FILE):
            print(f"错误：找不到 classpath 文件：{CLASSPATH_FILE}")
            return None
        
        with open(CLASSPATH_FILE, 'r', encoding='utf-8') as f:
            dependency_classpath = f.read().strip()
        
        # 完整 classpath = 测试类目录 + JAR + 依赖
        full_classpath = f"{test_class_dir};{JAR_PATH};{dependency_classpath}"
        
        # 编译 Java 文件
        javac_path = os.path.join(JDK_HOME, "bin", "javac.exe")
        compile_result = subprocess.run(
            [javac_path, "-d", test_class_dir, "-cp", f"{JAR_PATH};{dependency_classpath}", java_class_file],
            capture_output=True,
            text=True
        )
        
        if compile_result.returncode != 0:
            print(f"编译失败：{compile_result.stderr}")
            return None
        
        # 运行 Java 程序 - 使用完整 classpath
        # 在 Windows 上，需要使用 shell=True 来正确处理分号分隔的 classpath
        run_result = subprocess.run(
            f'"{JAVA_EXECUTABLE}" -cp "{full_classpath}" testcase.SM2InteropTest "{content}" "{enc_public_key_hex}" "{sign_private_key_hex}"',
            capture_output=True,
            text=True,
            shell=True
        )
        
        if run_result.returncode != 0:
            print(f"运行失败：{run_result.stderr}")
            return None
        
        # 解析输出
        output = run_result.stdout.strip()
        parts = output.split('\t')
        if len(parts) == 2:
            return {
                "ciphertext": parts[0],
                "signature": parts[1]
            }
        else:
            print(f"输出格式错误：{output}")
            return None
            
    finally:
        # 不清理编译后的类文件，可以复用
        pass

def main():
    """主函数"""
    print("=" * 60)
    print("Java SM2 加密和签名互操作性测试")
    print("=" * 60)
    
    # 检查 Java 可执行文件
    if not os.path.exists(JAVA_EXECUTABLE):
        print(f"错误：找不到 Java 可执行文件：{JAVA_EXECUTABLE}")
        sys.exit(1)
    
    # 检查 JAR 文件
    if not os.path.exists(JAR_PATH):
        print(f"错误：找不到 JAR 文件：{JAR_PATH}")
        sys.exit(1)
    
    # 检查密钥文件
    if not os.path.exists(KEYS_FILE):
        print(f"错误：找不到密钥文件：{KEYS_FILE}")
        sys.exit(1)
    
    # 检查测试数据文件
    if not os.path.exists(TEST_DATA_FILE):
        print(f"错误：找不到测试数据文件：{TEST_DATA_FILE}")
        sys.exit(1)
    
    # 加载密钥
    print(f"\n加载密钥文件：{KEYS_FILE}")
    keys = load_json_file(KEYS_FILE)
    enc_public_key_hex = keys["encryption_public_key"]["hex"]
    sign_private_key_hex = keys["signature_private_key"]["hex"]
    print(f"  加密公钥 (Hex): {enc_public_key_hex[:40]}...")
    print(f"  签名私钥 (Hex): {sign_private_key_hex[:40]}...")
    
    # 加载测试数据
    print(f"\n加载测试数据：{TEST_DATA_FILE}")
    test_data = load_json_file(TEST_DATA_FILE)
    test_cases = test_data["test_cases"]
    print(f"  测试用例数量：{len(test_cases)}")
    
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n输出目录：{OUTPUT_DIR}")
    
    # 处理每个测试用例
    results = []
    success_count = 0
    fail_count = 0
    
    for test_case in test_cases:
        test_id = test_case["id"]
        test_name = test_case["name"]
        plaintext = test_case["plaintext"]
        
        print(f"\n测试用例 {test_id}: {test_name}")
        print(f"  明文：{plaintext[:50]}{'...' if len(plaintext) > 50 else ''}")
        
        try:
            # 执行加密和签名
            result = run_java_command_v2(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("Java 命令执行失败")
            
            ciphertext = result["ciphertext"]
            signature = result["signature"]
            
            # 保存结果
            result_data = {
                "test_case_id": test_id,
                "test_case_name": test_name,
                "plaintext": plaintext,
                "ciphertext_hex": ciphertext,
                "signature_hex": signature
            }
            
            result_file = os.path.join(OUTPUT_DIR, f"test_{test_id}_{test_name}.json")
            save_json_file(result_file, result_data)
            print(f"  密文 (Hex): {ciphertext[:60]}...")
            print(f"  签名 (Hex): {signature[:60]}...")
            print(f"  结果已保存到：{result_file}")
            
            results.append(result_data)
            success_count += 1
            
        except Exception as e:
            print(f"  错误：{e}")
            fail_count += 1
    
    # 保存汇总结果
    summary_data = {
        "summary": {
            "total": len(test_cases),
            "success": success_count,
            "failed": fail_count
        },
        "results": results
    }
    
    summary_file = os.path.join(OUTPUT_DIR, "summary.json")
    save_json_file(summary_file, summary_data)
    print(f"\n汇总结果已保存到：{summary_file}")
    
    # 打印总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    print(f"总测试用例：{len(test_cases)}")
    print(f"成功：{success_count}")
    print(f"失败：{fail_count}")
    print(f"成功率：{success_count / len(test_cases) * 100:.1f}%")
    print("=" * 60)
    
    return 0 if fail_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())