#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java SM2 加密和 SM3 签名测试脚本

功能：
1. 读取或生成 SM2 密钥对（HEX 格式）并保存到 testcase/keys/java/keys.json
2. 使用 Java 对 test_data.json 中的测试数据（含英文、简体中文、繁体中文）进行 SM2 加密和 SM3 签名
3. 将加密结果（密文 HEX、签名 HEX）保存到 testcase/results/java_encrypt/ 目录
4. 直接调用 Java JAR 文件执行加密签名操作
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# 配置路径
JDK_HOME = r"H:\Programs\Java\jdk-21.0.1+12"
JAVA_EXECUTABLE = os.path.join(JDK_HOME, "bin", "java.exe")
JAVAC_EXECUTABLE = os.path.join(JDK_HOME, "bin", "javac.exe")
JAR_PATH = "java/crossmool/target/crossmool-1.1.0.jar"
CLASSPATH_FILE = "java/crossmool/classpath.txt"
KEYS_FILE = "testcase/keys/java/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/java_encrypt"
TEST_CLASS_DIR = "testcase/java_test_classes"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def generate_key_pair():
    """
    调用 Java 生成 SM2 密钥对（HEX 格式）
    
    返回:
        dict: 包含公钥和私钥 HEX 的字典
    """
    os.makedirs(TEST_CLASS_DIR, exist_ok=True)
    java_class_file = os.path.join(TEST_CLASS_DIR, "KeyPairGenerator.java")
    
    java_code = """package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.SerialKeyPair;

public class KeyPairGenerator {
    public static void main(String[] args) {
        try {
            SerialKeyPair keyPair = SM2Util.generateKeyPairHex();
            System.out.println("PUBLIC:" + keyPair.getPublicKey());
            System.out.println("PRIVATE:" + keyPair.getPrivateKey());
        } catch (Exception e) {
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
"""
    
    with open(java_class_file, 'w', encoding='utf-8') as f:
        f.write(java_code)
    
    try:
        if not os.path.exists(CLASSPATH_FILE):
            print(f"错误：找不到 classpath 文件：{CLASSPATH_FILE}")
            return None
        
        with open(CLASSPATH_FILE, 'r', encoding='utf-8') as f:
            dependency_classpath = f.read().strip()
        
        full_classpath = f"{TEST_CLASS_DIR};{JAR_PATH};{dependency_classpath}"
        
        compile_result = subprocess.run(
            [JAVAC_EXECUTABLE, "-d", TEST_CLASS_DIR, "-cp", f"{JAR_PATH};{dependency_classpath}", java_class_file],
            capture_output=True,
            text=True
        )
        
        if compile_result.returncode != 0:
            print(f"编译失败：{compile_result.stderr}")
            return None
        
        run_result = subprocess.run(
            f'"{JAVA_EXECUTABLE}" -cp "{full_classpath}" testcase.KeyPairGenerator',
            capture_output=True,
            text=True,
            shell=True
        )
        
        if run_result.returncode != 0:
            print(f"运行失败：{run_result.stderr}")
            return None
        
        output = run_result.stdout.strip()
        public_key = None
        private_key = None
        
        for line in output.split('\n'):
            if line.startswith("PUBLIC:"):
                public_key = line[7:]
            elif line.startswith("PRIVATE:"):
                private_key = line[8:]
        
        if public_key and private_key:
            return {
                "encryption_public_key": {"hex": public_key},
                "signature_private_key": {"hex": private_key}
            }
        else:
            print(f"输出格式错误：{output}")
            return None
            
    finally:
        if os.path.exists(java_class_file):
            os.remove(java_class_file)

def load_or_generate_keys():
    """
    加载密钥文件，如果不存在则生成新的密钥对
    
    返回:
        dict: 密钥字典
    """
    if os.path.exists(KEYS_FILE):
        print(f"加载现有密钥文件：{KEYS_FILE}")
        keys = load_json_file(KEYS_FILE)
        print(f"  加密公钥 (Hex): {keys['encryption_public_key']['hex'][:40]}...")
        print(f"  签名私钥 (Hex): {keys['signature_private_key']['hex'][:40]}...")
        return keys
    else:
        print(f"密钥文件不存在，生成新密钥对：{KEYS_FILE}")
        keys = generate_key_pair()
        if keys:
            save_json_file(KEYS_FILE, keys)
            print(f"密钥已保存到：{KEYS_FILE}")
            return keys
        else:
            print("错误：生成密钥对失败")
            sys.exit(1)

def run_java_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    """
    运行 Java 命令执行 SM2 加密和 SM3 签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    os.makedirs(TEST_CLASS_DIR, exist_ok=True)
    java_class_file = os.path.join(TEST_CLASS_DIR, "SM2EncryptSignTest.java")
    input_file = os.path.join(TEST_CLASS_DIR, "input.txt")
    
    # 将内容写入临时文件，避免命令行转义问题
    with open(input_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    java_code = '''package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SM2EncryptSignTest {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: SM2EncryptSignTest <encPublicKey> <signPrivateKey>");
            System.exit(1);
        }
        
        String encPublicKey = args[0];
        String signPrivateKey = args[1];
        
        try {
            String content = Files.readString(Paths.get("g:/workspaces/git/corssmool/crossmool/testcase/java_test_classes/input.txt"));
            CiphertextSignaturePair result = SM2Util.encryptSign(content, encPublicKey, signPrivateKey, false);
            System.out.println(result.getCiphertext() + "\\t" + result.getSignature());
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
    
    try:
        if not os.path.exists(CLASSPATH_FILE):
            print(f"错误：找不到 classpath 文件：{CLASSPATH_FILE}")
            return None
        
        with open(CLASSPATH_FILE, 'r', encoding='utf-8') as f:
            dependency_classpath = f.read().strip()
        
        full_classpath = f"{TEST_CLASS_DIR};{JAR_PATH};{dependency_classpath}"
        
        compile_result = subprocess.run(
            [JAVAC_EXECUTABLE, "-d", TEST_CLASS_DIR, "-cp", f"{JAR_PATH};{dependency_classpath}", java_class_file],
            capture_output=True,
            text=True
        )
        
        if compile_result.returncode != 0:
            print(f"  编译失败：{compile_result.stderr}")
            print(f"  编译 STDOUT: {compile_result.stdout}")
            return None
        
        run_result = subprocess.run(
            f'"{JAVA_EXECUTABLE}" -cp "{full_classpath}" testcase.SM2EncryptSignTest "{enc_public_key_hex}" "{sign_private_key_hex}"',
            capture_output=True,
            text=True,
            shell=True
        )
        
        if run_result.returncode != 0:
            print(f"  运行失败：{run_result.stderr}")
            print(f"  运行 STDOUT: {run_result.stdout}")
            return None
        
        output = run_result.stdout.strip()
        print(f"  Java 输出：{output[:200]}...")
        parts = output.split('\t')
        if len(parts) == 2:
            return {"ciphertext": parts[0], "signature": parts[1]}
        else:
            print(f"  输出格式错误：期望 2 个部分，实际 {len(parts)} 个")
            print(f"  完整输出：{output}")
            return None
            
    finally:
        if os.path.exists(java_class_file):
            os.remove(java_class_file)

def main():
    """主函数"""
    print("=" * 60)
    print("Java SM2 加密和 SM3 签名测试")
    print("=" * 60)
    
    if not os.path.exists(JAVA_EXECUTABLE):
        print(f"错误：找不到 Java 可执行文件：{JAVA_EXECUTABLE}")
        sys.exit(1)
    
    if not os.path.exists(JAR_PATH):
        print(f"错误：找不到 JAR 文件：{JAR_PATH}")
        sys.exit(1)
    
    keys = load_or_generate_keys()
    enc_public_key_hex = keys["encryption_public_key"]["hex"]
    sign_private_key_hex = keys["signature_private_key"]["hex"]
    
    if not os.path.exists(TEST_DATA_FILE):
        print(f"错误：找不到测试数据文件：{TEST_DATA_FILE}")
        sys.exit(1)
    
    print(f"\n加载测试数据：{TEST_DATA_FILE}")
    test_data = load_json_file(TEST_DATA_FILE)
    test_cases = test_data["test_cases"]
    print(f"  测试用例数量：{len(test_cases)}")
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n输出目录：{OUTPUT_DIR}")
    
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
            result = run_java_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("Java 命令执行失败")
            
            ciphertext = result["ciphertext"]
            signature = result["signature"]
            
            # 验证 HEX 格式
            if not all(c in '0123456789abcdefABCDEF' for c in ciphertext):
                raise Exception(f"密文不是有效的 HEX 格式：{ciphertext[:50]}...")
            if not all(c in '0123456789abcdefABCDEF' for c in signature):
                raise Exception(f"签名不是有效的 HEX 格式：{signature[:50]}...")
            
            result_data = {
                "test_case_id": test_id,
                "test_case_name": test_name,
                "plaintext": plaintext,
                "ciphertext_hex": ciphertext,
                "signature_hex": signature
            }
            
            safe_test_name = test_name.replace(" ", "_").replace("special_characters", "special_chars")
            result_file = os.path.join(OUTPUT_DIR, f"test_{test_id}_{safe_test_name}.json")
            save_json_file(result_file, result_data)
            print(f"  密文 (Hex): {ciphertext[:60]}...")
            print(f"  签名 (Hex): {signature[:60]}...")
            print(f"  结果已保存到：{result_file}")
            
            results.append(result_data)
            success_count += 1
            
        except Exception as e:
            error_msg = str(e)
            print(f"  ❌ 错误：{error_msg}")
            print(f"  异常类型：{type(e).__name__}")
            import traceback
            traceback.print_exc()
            fail_count += 1
            # 保存失败记录
            error_data = {
                "test_case_id": test_id,
                "test_case_name": test_name,
                "error": error_msg
            }
            error_file = os.path.join(OUTPUT_DIR, f"test_{test_id}_{test_name}_error.json")
            try:
                save_json_file(error_file, error_data)
            except Exception:
                pass
    
    summary_data = {
        "summary": {"total": len(test_cases), "success": success_count, "failed": fail_count},
        "results": results
    }
    
    summary_file = os.path.join(OUTPUT_DIR, "summary.json")
    save_json_file(summary_file, summary_data)
    print(f"\n汇总结果已保存到：{summary_file}")
    
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
