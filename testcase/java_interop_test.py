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
import base64
from pathlib import Path

# 配置路径
JDK_HOME = r"D:\Programs\Java\jdk-17.0.9+9"
JAVA_EXECUTABLE = os.path.join(JDK_HOME, "bin", "java.exe")
JAR_PATH = "java/crossmool/target/crossmool-1.1.0.jar"
CLASSPATH_FILE = "java/crossmool/classpath.txt"
KEYS_FILE = "testcase/keys/java/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/java_encrypt"

def load_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def get_full_classpath():
    if not os.path.exists(CLASSPATH_FILE):
        return JAR_PATH
    with open(CLASSPATH_FILE, 'r', encoding='utf-8') as f:
        dependency_classpath = f.read().strip()
    return f"{JAR_PATH};{dependency_classpath}"

def ensure_java_encrypt_class():
    """Ensure the SM2InteropTest.java is compiled and ready."""
    test_class_dir = "testcase/java_test_classes"
    os.makedirs(test_class_dir, exist_ok=True)
    
    java_class_file = os.path.join(test_class_dir, "SM2InteropTest.java")
    class_file = os.path.join(test_class_dir, "testcase", "SM2InteropTest.class")
    
    # Check if already compiled
    if os.path.exists(class_file):
        return test_class_dir
    
    java_code = '''package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class SM2InteropTest {
    public static void main(String[] args) throws Exception {
        String mode = args[0];
        
        if (mode.equals("encrypt")) {
            // Read content from file (base64 encoded to preserve special chars)
            String contentB64 = args[1];
            String encPublicKey = args[2];
            String signPrivateKey = args[3];
            
            String content = new String(Base64.getDecoder().decode(contentB64), "UTF-8");
            CiphertextSignaturePair result = SM2Util.encryptSign(content, encPublicKey, signPrivateKey, false);
            System.out.println(result.getCiphertext() + "\\t" + result.getSignature());
            
        } else if (mode.equals("verify_decrypt")) {
            // Read input from JSON file
            String inputFile = args[1];
            String inputJson = new String(Files.readAllBytes(Paths.get(inputFile)), "UTF-8");
            
            // Simple JSON parsing
            String ciphertextHex = extractJsonField(inputJson, "ciphertext_hex");
            String signatureHex = extractJsonField(inputJson, "signature_hex");
            String signPublicKey = extractJsonField(inputJson, "sign_public_key_hex");
            String decPrivateKey = extractJsonField(inputJson, "dec_private_key_hex");
            
            String decrypted = SM2Util.verifyDecrypt(ciphertextHex, signatureHex, signPublicKey, decPrivateKey);
            // Output as Base64 to preserve special chars
            String b64 = Base64.getEncoder().encodeToString(decrypted.getBytes("UTF-8"));
            System.out.println("SUCCESS:" + b64);
        }
    }
    
    static String extractJsonField(String json, String key) {
        String searchKey = "\\"" + key + "\\":\\u0020*\\"";
        int idx = json.indexOf("\\"" + key + "\\"");
        if (idx < 0) throw new RuntimeException("Field not found: " + key);
        // Find the colon after key
        int colon = json.indexOf(':', idx);
        // Find the opening quote of value
        int openQuote = json.indexOf('"', colon);
        // Find the closing quote
        int closeQuote = json.indexOf('"', openQuote + 1);
        // Handle escaped quotes
        while (closeQuote > 0 && json.charAt(closeQuote - 1) == '\\\\' && json.charAt(closeQuote - 2) != '\\\\') {
            closeQuote = json.indexOf('"', closeQuote + 1);
        }
        return json.substring(openQuote + 1, closeQuote);
    }
}
'''
    
    with open(java_class_file, 'w', encoding='utf-8') as f:
        f.write(java_code)
    
    full_cp = get_full_classpath()
    javac_path = os.path.join(JDK_HOME, "bin", "javac.exe")
    compile_result = subprocess.run(
        [javac_path, "-d", test_class_dir, "-cp", full_cp, java_class_file],
        capture_output=True, text=True
    )
    
    if compile_result.returncode != 0:
        print(f"编译失败：{compile_result.stderr}")
        sys.exit(1)
    
    return test_class_dir

def run_java_encrypt(content, enc_public_key_hex, sign_private_key_hex):
    """Run Java encrypt+sign, using base64 to pass content safely."""
    test_class_dir = ensure_java_encrypt_class()
    full_cp = f"{test_class_dir};{get_full_classpath()}"
    
    # Encode content as base64 to avoid command-line special char issues
    content_b64 = base64.b64encode(content.encode('utf-8')).decode('ascii')
    
    run_result = subprocess.run(
        [JAVA_EXECUTABLE, "-cp", full_cp, "testcase.SM2InteropTest",
         "encrypt", content_b64, enc_public_key_hex, sign_private_key_hex],
        capture_output=True, text=True
    )
    
    if run_result.returncode != 0:
        print(f"运行失败：{run_result.stderr}")
        return None
    
    output = run_result.stdout.strip()
    parts = output.split('\t')
    if len(parts) == 2:
        return {"ciphertext": parts[0], "signature": parts[1]}
    else:
        print(f"输出格式错误：{output}")
        return None

def main():
    print("=" * 60)
    print("Java SM2 加密和签名互操作性测试")
    print("=" * 60)
    
    if not os.path.exists(JAVA_EXECUTABLE):
        print(f"错误：找不到 Java 可执行文件：{JAVA_EXECUTABLE}")
        sys.exit(1)
    
    if not os.path.exists(JAR_PATH):
        print(f"错误：找不到 JAR 文件：{JAR_PATH}")
        sys.exit(1)
    
    if not os.path.exists(KEYS_FILE):
        print(f"错误：找不到密钥文件：{KEYS_FILE}")
        sys.exit(1)
    
    if not os.path.exists(TEST_DATA_FILE):
        print(f"错误：找不到测试数据文件：{TEST_DATA_FILE}")
        sys.exit(1)
    
    print(f"\n加载密钥文件：{KEYS_FILE}")
    keys = load_json_file(KEYS_FILE)
    enc_public_key_hex = keys["encryption_public_key"]["hex"]
    sign_private_key_hex = keys["signature_private_key"]["hex"]
    print(f"  加密公钥 (Hex): {enc_public_key_hex[:40]}...")
    print(f"  签名私钥 (Hex): {sign_private_key_hex[:40]}...")
    
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
            result = run_java_encrypt(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("Java 命令执行失败")
            
            ciphertext = result["ciphertext"]
            signature = result["signature"]
            
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
