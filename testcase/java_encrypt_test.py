#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java SM2 密钥生成和加密测试脚本

功能：
1. 调用 Java SM2Util.generateKeyPairHex() 生成 SM2 密钥对（HEX 格式）
2. 保存密钥到 testcase/keys/java/keys.json
3. 使用 SM2Util.encryptSign() 加密和签名测试数据（HEX 输出格式）
4. 保存结果到 testcase/results/java_encrypt/ 目录

测试数据包括：
- 英文文本
- 简体中文
- 繁体中文
- 混合内容
- 特殊字符
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

def generate_key_pair_hex():
    """
    调用 Java SM2Util.generateKeyPairHex() 生成密钥对
    通过过滤日志行来提取纯密钥数据
    
    返回:
        dict: 包含公钥和私钥的字典
    """
    import re
    
    # [MARKER] 函数入口调试
    print(f"[FUNC_ENTER] generate_key_pair_hex called")
    
    # 创建 Java 测试类
    os.makedirs(TEST_CLASS_DIR, exist_ok=True)
    java_class_file = os.path.join(TEST_CLASS_DIR, "SM2KeyGenTest.java")
    
    java_code = '''package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.SerialKeyPair;

public class SM2KeyGenTest {
    public static void main(String[] args) {
        try {
            SerialKeyPair keyPair = SM2Util.generateKeyPairHex();
            // 输出纯密钥数据到 stdout，每行一个
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
    
    try:
        # 读取 classpath 文件
        if not os.path.exists(CLASSPATH_FILE):
            print(f"错误：找不到 classpath 文件：{CLASSPATH_FILE}")
            return None
        
        with open(CLASSPATH_FILE, 'r', encoding='utf-8') as f:
            dependency_classpath = f.read().strip()
        
        # 完整 classpath = 测试类目录 + JAR + 依赖
        full_classpath = f"{TEST_CLASS_DIR};{JAR_PATH};{dependency_classpath}"
        
        # 编译 Java 文件
        compile_result = subprocess.run(
            [JAVAC_EXECUTABLE, "-d", TEST_CLASS_DIR, "-cp", f"{JAR_PATH};{dependency_classpath}", java_class_file],
            capture_output=True,
            text=True
        )
        
        if compile_result.returncode != 0:
            print(f"编译失败：{compile_result.stdout}")
            print(f"编译错误：{compile_result.stderr}")
            import sys
            sys.exit(1)
        
        # 运行 Java 程序
        run_result = subprocess.run(
            f'"{JAVA_EXECUTABLE}" -cp "{full_classpath}" testcase.SM2KeyGenTest',
            capture_output=True,
            text=True,
            shell=True
        )
        
        if run_result.returncode != 0:
            print(f"运行失败：{run_result.stderr}")
            return None
        
        # 从 stdout 解析输出
        output = run_result.stdout.strip()
        
        public_key = None
        private_key = None
        
        # 输出格式：12:00:43.661 [main] INFO ... -- \npublicKeyStr:...\nprivateKeyStr:...\n公钥\n私钥
        # 直接使用正则表达式提取 publicKeyStr: 和 privateKeyStr: 后的 HEX 字符串
        pub_match = re.search(r'publicKeyStr:([0-9a-fA-F]{60,})', output, re.IGNORECASE)
        pri_match = re.search(r'privateKeyStr:([0-9a-fA-F]{60,})', output, re.IGNORECASE)
        if pub_match and pri_match:
            public_key = pub_match.group(1)
            private_key = pri_match.group(1)
            print(f"  [INFO] 正则表达式提取成功")
            print(f"  [INFO] 公钥：{public_key[:30]}...")
            print(f"  [INFO] 私钥：{private_key[:30]}...")
        else:
            # 备用方案：逐行解析
            print(f"  [WARN] 正则表达式失败，尝试逐行解析")
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                # 跳过日志行
                if re.match(r'^\d{2}:\d{2}:\d{2}', line) or 'INFO' in line or 'ERROR' in line:
                    continue
                # 跳过带前缀的行
                if line.startswith('publicKeyStr:') or line.startswith('privateKeyStr:'):
                    continue
                # 查找以"30"开头的 DER 编码密钥（长度>100）
                if line.startswith('30') and len(line) > 100:
                    if public_key is None:
                        public_key = line
                    elif private_key is None:
                        private_key = line
                        break
        
        if public_key and private_key:
            print(f"  [DEBUG] Java 生成公钥：{public_key[:20]}...")
            print(f"  [DEBUG] Java 生成私钥：{private_key[:20]}...")
            return {
                "public_key": public_key,
                "private_key": private_key
            }
        
        print(f"输出格式错误：{run_result.stdout}")
        print(f"stderr: {run_result.stderr}")
        return None
            
    finally:
        pass

def run_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    """
    运行 Java 命令执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 创建 Java 测试类
    os.makedirs(TEST_CLASS_DIR, exist_ok=True)
    java_class_file = os.path.join(TEST_CLASS_DIR, "SM2EncryptSignTest.java")
    
    # 转义内容中的特殊字符
    escaped_content = content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t').replace('\r', '\\r')
    
    java_code = f'''package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

public class SM2EncryptSignTest {{
    public static void main(String[] args) {{
        String content = "{escaped_content}";
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
        full_classpath = f"{TEST_CLASS_DIR};{JAR_PATH};{dependency_classpath}"
        
        # 编译 Java 文件
        compile_result = subprocess.run(
            [JAVAC_EXECUTABLE, "-d", TEST_CLASS_DIR, "-cp", f"{JAR_PATH};{dependency_classpath}", java_class_file],
            capture_output=True,
            text=True
        )
        
        if compile_result.returncode != 0:
            print(f"编译失败：{compile_result.stderr}")
            return None
        
        # 运行 Java 程序
        run_result = subprocess.run(
            f'"{JAVA_EXECUTABLE}" -cp "{full_classpath}" testcase.SM2EncryptSignTest',
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
        pass

def main():
    """主函数"""
    print("=" * 60)
    print("Java SM2 密钥生成和加密测试")
    print("=" * 60)
    
    # 检查 Java 可执行文件
    if not os.path.exists(JAVA_EXECUTABLE):
        print(f"错误：找不到 Java 可执行文件：{JAVA_EXECUTABLE}")
        sys.exit(1)
    
    # 检查 JAR 文件
    if not os.path.exists(JAR_PATH):
        print(f"错误：找不到 JAR 文件：{JAR_PATH}")
        sys.exit(1)
    
    # 检查 classpath 文件
    if not os.path.exists(CLASSPATH_FILE):
        print(f"错误：找不到 classpath 文件：{CLASSPATH_FILE}")
        sys.exit(1)
    
    # 检查测试数据文件
    if not os.path.exists(TEST_DATA_FILE):
        print(f"错误：找不到测试数据文件：{TEST_DATA_FILE}")
        sys.exit(1)
    
    # 生成密钥对
    print("\n生成 SM2 密钥对（HEX 格式）...")
    key_pair = generate_key_pair_hex()
    
    if key_pair is None:
        print("错误：密钥生成失败")
        sys.exit(1)
    
    enc_public_key_hex = key_pair["public_key"]
    sign_private_key_hex = key_pair["private_key"]
    
    print(f"  加密公钥 (Hex): {enc_public_key_hex[:40]}...")
    print(f"  签名私钥 (Hex): {sign_private_key_hex[:40]}...")
    
    # 保存密钥到文件
    keys_data = {
        "encryption_public_key": {
            "hex": enc_public_key_hex,
            "format": "X.509 HEX"
        },
        "encryption_private_key": {
            "hex": sign_private_key_hex,
            "format": "PKCS#8 HEX"
        },
        "signature_private_key": {
            "hex": sign_private_key_hex,
            "format": "PKCS#8 HEX"
        },
        "signature_public_key": {
            "hex": enc_public_key_hex,
            "format": "X.509 HEX"
        }
    }
    save_json_file(KEYS_FILE, keys_data)
    print(f"  密钥已保存到：{KEYS_FILE}")
    
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
            result = run_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
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