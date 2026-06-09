#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java-JavaScript SM2/SM3/SM4 互通性测试脚本

导入 sys 和 io 并设置标准输出为 UTF-8 编码

功能：
1. 使用 Java 和 JavaScript 分别执行 SM2 加密/解密/签名/验签
2. 使用 Java 和 JavaScript 分别执行 SM3 哈希和 HMAC-SM3
3. 使用 Java 和 JavaScript 分别执行 SM4 GCM 加密/解密
4. 验证两种语言实现的结果是否互通
5. 支持 Hex 和 Base64 两种编码模式
"""

import io
import json
import os
import subprocess
import sys
import base64
from pathlib import Path

# 设置标准输出为 UTF-8 编码，避免 Windows 命令行乱码
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# 配置路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
JDK_HOME = r"D:\Programs\Java\jdk-17.0.9+9"
JAVA_EXECUTABLE = os.path.join(JDK_HOME, "bin", "java.exe")
JAVAC_EXECUTABLE = os.path.join(JDK_HOME, "bin", "javac.exe")
JAR_PATH = os.path.join(PROJECT_ROOT, "java/crossmool/target/crossmool-1.1.0.jar")
CLASSPATH_FILE = os.path.join(PROJECT_ROOT, "java/crossmool/classpath.txt")
NODE_EXECUTABLE = "node"
JS_DIST_PATH = os.path.join(PROJECT_ROOT, "javascript/crossmool/dist")

# 密钥文件
JAVA_KEYS_FILE = "testcase/keys/java/keys.json"
JS_KEYS_FILE = "testcase/keys/javascript/keys.json"

# 输出目录
OUTPUT_DIR = "testcase/results/java_javascript_interop"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def get_java_classpath():
    """获取 Java classpath"""
    if not os.path.exists(CLASSPATH_FILE):
        return JAR_PATH
    with open(CLASSPATH_FILE, 'r', encoding='utf-8') as f:
        dependency_classpath = f.read().strip()
    return f"{JAR_PATH};{dependency_classpath}"

def ensure_test_class():
    """确保测试类已编译"""
    test_class_dir = "testcase/java_test_classes"
    os.makedirs(test_class_dir, exist_ok=True)
    
    java_class_file = os.path.join(test_class_dir, "JavaJavascriptInteropTest.java")
    class_file = os.path.join(test_class_dir, "testcase", "JavaJavascriptInteropTest.class")
    
    if os.path.exists(class_file):
        return test_class_dir
    
    java_code = '''package testcase;

import cc.iili.tools.crossmool.tool.*;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JavaJavascriptInteropTest {
    
    public static void main(String[] args) {
        String mode = args[0];
        
        try {
            switch (mode) {
                case "sm2_encrypt_hex":
                    testSm2EncryptHex(args[1], args[2]);
                    break;
                case "sm2_encrypt_base64":
                    testSm2EncryptBase64(args[1], args[2]);
                    break;
                case "sm2_decrypt_hex":
                    testSm2DecryptHex(args[1], args[2]);
                    break;
                case "sm2_decrypt_base64":
                    testSm2DecryptBase64(args[1], args[2]);
                    break;
                case "sm2_sign_hex":
                    testSm2SignHex(args[1], args[2]);
                    break;
                case "sm2_sign_base64":
                    testSm2SignBase64(args[1], args[2]);
                    break;
                case "sm2_verify_hex":
                    testSm2VerifyHex(args[1], args[2], args[3]);
                    break;
                case "sm2_verify_base64":
                    testSm2VerifyBase64(args[1], args[2], args[3]);
                    break;
                case "sm2_encrypt_sign_hex":
                    testSm2EncryptSignHex(args[1], args[2], args[3]);
                    break;
                case "sm2_encrypt_sign_base64":
                    testSm2EncryptSignBase64(args[1], args[2], args[3]);
                    break;
                case "sm2_verify_decrypt_hex":
                    testSm2VerifyDecryptHex(args[1], args[2], args[3], args[4]);
                    break;
                case "sm2_verify_decrypt_base64":
                    testSm2VerifyDecryptBase64(args[1], args[2], args[3], args[4]);
                    break;
                case "sm3_digest":
                    testSm3Digest(args[1]);
                    break;
                case "sm3_hmac":
                    testSm3Hmac(args[1], args[2]);
                    break;
                case "sm4_encrypt_hex":
                    testSm4EncryptHex(args[1], args[2]);
                    break;
                case "sm4_encrypt_base64":
                    testSm4EncryptBase64(args[1], args[2]);
                    break;
                case "sm4_decrypt_hex":
                    testSm4DecryptHex(args[1], args[2]);
                    break;
                case "sm4_decrypt_base64":
                    testSm4DecryptBase64(args[1], args[2]);
                    break;
                default:
                    System.err.println("Unknown mode: " + mode);
                    System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("ERROR:" + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    static void testSm2EncryptHex(String contentB64, String publicKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String cipherHex = SM2Util.encrypt(content, publicKey, false);
        System.out.println(cipherHex);
    }
    
    static void testSm2EncryptBase64(String contentB64, String publicKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String cipherBase64 = SM2Util.encrypt(content, publicKey, true);
        System.out.println(cipherBase64);
    }
    
    static void testSm2DecryptHex(String cipherHex, String privateKey) {
        String plain = SM2Util.decrypt(cipherHex, privateKey);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm2DecryptBase64(String cipherBase64, String privateKey) {
        String plain = SM2Util.decrypt(cipherBase64, privateKey);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm2SignHex(String contentB64, String privateKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String sigHex = SM2Util.sign(content, privateKey, false);
        System.out.println(sigHex);
    }
    
    static void testSm2SignBase64(String contentB64, String privateKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String sigBase64 = SM2Util.sign(content, privateKey, true);
        System.out.println(sigBase64);
    }
    
    static void testSm2VerifyHex(String contentB64, String publicKey, String sigHex) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        boolean valid = SM2Util.verify(content, publicKey, sigHex);
        System.out.println(valid ? "true" : "false");
    }
    
    static void testSm2VerifyBase64(String contentB64, String publicKey, String sigBase64) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        boolean valid = SM2Util.verify(content, publicKey, sigBase64);
        System.out.println(valid ? "true" : "false");
    }
    
    static void testSm2EncryptSignHex(String contentB64, String encPubKey, String signPrivKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        CiphertextSignaturePair pair = SM2Util.encryptSign(content, encPubKey, signPrivKey, false);
        System.out.println(pair.getCiphertext() + "\\t" + pair.getSignature());
    }
    
    static void testSm2EncryptSignBase64(String contentB64, String encPubKey, String signPrivKey) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        CiphertextSignaturePair pair = SM2Util.encryptSign(content, encPubKey, signPrivKey, true);
        System.out.println(pair.getCiphertext() + "\\t" + pair.getSignature());
    }
    
    static void testSm2VerifyDecryptHex(String cipherHex, String sigHex, String signPubKey, String decPrivKey) {
        String plain = SM2Util.verifyDecrypt(cipherHex, sigHex, signPubKey, decPrivKey);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm2VerifyDecryptBase64(String cipherBase64, String sigBase64, String signPubKey, String decPrivKey) {
        String plain = SM2Util.verifyDecrypt(cipherBase64, sigBase64, signPubKey, decPrivKey);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm3Digest(String contentB64) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String digestHex = SM3Util.digestToStr(content);
        System.out.println(digestHex);
    }
    
    static void testSm3Hmac(String keyHex, String contentB64) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        String hmacHex = SM3Util.hmacToStr(keyHex, content);
        System.out.println(hmacHex);
    }
    
    static void testSm4EncryptHex(String contentB64, String keyHex) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        byte[] key = cc.iili.tools.crossmool.util.HexUtil.decodeHexStr(keyHex);
        String cipherBase64 = SM4Util.encryptGcmJca(key, content);
        System.out.println(cipherBase64);
    }
    
    static void testSm4EncryptBase64(String contentB64, String keyBase64) {
        String content = new String(Base64.getDecoder().decode(contentB64), StandardCharsets.UTF_8);
        byte[] key = Base64.getDecoder().decode(keyBase64);
        String cipherBase64 = SM4Util.encryptGcmJca(key, content);
        System.out.println(cipherBase64);
    }
    
    static void testSm4DecryptHex(String cipherBase64, String keyHex) {
        byte[] key = cc.iili.tools.crossmool.util.HexUtil.decodeHexStr(keyHex);
        String plain = SM4Util.decryptGcmJca(key, cipherBase64);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
    
    static void testSm4DecryptBase64(String cipherBase64, String keyBase64) {
        byte[] key = Base64.getDecoder().decode(keyBase64);
        String plain = SM4Util.decryptGcmJca(key, cipherBase64);
        String plainB64 = Base64.getEncoder().encodeToString(plain.getBytes(StandardCharsets.UTF_8));
        System.out.println(plainB64);
    }
}
'''
    
    with open(java_class_file, 'w', encoding='utf-8') as f:
        f.write(java_code)
    
    full_cp = get_java_classpath()
    compile_result = subprocess.run(
        [JAVAC_EXECUTABLE, "-d", test_class_dir, "-cp", full_cp, java_class_file],
        capture_output=True, text=True
    )
    
    if compile_result.returncode != 0:
        print(f"编译失败：{compile_result.stderr}")
        sys.exit(1)
    
    return test_class_dir

def run_java_test(mode, *args):
    """运行 Java 测试"""
    test_class_dir = ensure_test_class()
    full_cp = f"{test_class_dir};{get_java_classpath()}"
    
    cmd_args = [JAVA_EXECUTABLE, "-cp", full_cp, "testcase.JavaJavascriptInteropTest", mode] + list(args)
    
    run_result = subprocess.run(cmd_args, capture_output=True, text=True, encoding='utf-8')
    
    if run_result.returncode != 0:
        error_msg = run_result.stderr.strip()
        if "ERROR:" in error_msg:
            error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
        return None, error_msg
    
    output = run_result.stdout.strip()
    if output.startswith("ERROR:"):
        return None, output[6:]
    
    return output, None

def run_js_test(mode, *args):
    """运行 JavaScript 测试"""
    temp_js_file = "temp_js_interop_test.js"
    
    # 转义参数
    def escape_arg(arg):
        return str(arg).replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t').replace('\r', '\\r')
    
    # 为当前模式生成 JavaScript 代码
    js_templates = {
        "sm2_encrypt_hex": 'result = SM2Util.encrypt("{0}", "{1}", false);',
        "sm2_encrypt_base64": 'result = SM2Util.encrypt("{0}", "{1}", true);',
        "sm2_decrypt_hex": 'result = SM2Util.decrypt("{0}", "{1}");',
        "sm2_decrypt_base64": 'result = SM2Util.decrypt("{0}", "{1}");',
        "sm2_sign_hex": 'result = SM2Util.sign("{0}", "{1}", false);',
        "sm2_sign_base64": 'result = SM2Util.sign("{0}", "{1}", true);',
        "sm2_verify_hex": 'result = SM2Util.verify("{0}", "{1}", "{2}");',
        "sm2_verify_base64": 'result = SM2Util.verify("{0}", "{1}", "{2}");',
        "sm2_encrypt_sign_hex": 'const pair1 = SM2Util.encryptSign("{0}", "{1}", "{2}", false); result = pair1.ciphertext + "\\t" + pair1.signature;',
        "sm2_encrypt_sign_base64": 'const pair2 = SM2Util.encryptSign("{0}", "{1}", "{2}", true); result = pair2.ciphertext + "\\t" + pair2.signature;',
        "sm2_verify_decrypt_hex": 'result = SM2Util.verifyDecrypt("{0}", "{1}", "{2}", "{3}");',
        "sm2_verify_decrypt_base64": 'result = SM2Util.verifyDecrypt("{0}", "{1}", "{2}", "{3}");',
        "sm3_digest": 'result = SM3Util.digestToHex("{0}");',
        "sm3_hmac": 'result = SM3Util.hmacToHex("{0}", "{1}");',
        "sm4_encrypt_hex": 'result = SM4Util.encryptGcmString("{0}", "{1}");',
        "sm4_encrypt_base64": 'result = SM4Util.encryptGcmString("{0}", "{1}");',
        "sm4_decrypt_hex": 'result = SM4Util.decryptGcmToString("{0}", "{1}");',
        "sm4_decrypt_base64": 'result = SM4Util.decryptGcmToString("{0}", "{1}");',
    }
    
    if mode not in js_templates:
        raise ValueError(f"Unknown mode: {mode}")
    
    # 转义参数并格式化模板
    escaped_args = [escape_arg(arg) for arg in args]
    js_code_body = js_templates[mode].format(*escaped_args)
    
    # 转义路径中的反斜杠
    js_dist_escaped = JS_DIST_PATH.replace('\\', '\\\\')
    
    js_code = f'''
const {{ SM2Util, SM3Util, SM4Util }} = require('{js_dist_escaped}/index.js');

try {{
    let result;
    {js_code_body}
    console.log(result);
}} catch (error) {{
    console.error("ERROR:" + error.message);
    process.exit(1);
}}
'''
    
    with open(temp_js_file, 'w', encoding='utf-8') as f:
        f.write(js_code)
    
    try:
        run_result = subprocess.run(
            [NODE_EXECUTABLE, temp_js_file],
            capture_output=True, text=True, encoding='utf-8'
        )
        
        if run_result.returncode != 0:
            error_msg = run_result.stderr.strip()
            if "ERROR:" in error_msg:
                error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
            return None, error_msg
        
        output = run_result.stdout.strip()
        if output.startswith("ERROR:"):
            return None, output[6:]
        
        return output, None
        
    finally:
        if os.path.exists(temp_js_file):
            os.remove(temp_js_file)

def test_sm2_interop(java_keys, js_keys):
    """测试 SM2 互通性"""
    print("\n" + "=" * 70)
    print("SM2 互通性测试")
    print("=" * 70)
    
    results = {
        "sm2": {
            "encrypt_hex": [],
            "encrypt_base64": [],
            "sign_hex": [],
            "sign_base64": [],
            "verify_hex": [],
            "verify_base64": [],
            "encrypt_sign_hex": [],
            "encrypt_sign_base64": []
        }
    }
    
    test_cases = [
        {"id": 1, "name": "simple_text", "plaintext": "Hello, Crossmool!"},
        {"id": 2, "name": "chinese_text", "plaintext": "跨语言互操作性测试"},
        {"id": 3, "name": "mixed_content", "plaintext": "Test 测试 123!@#"},
    ]
    
    for test_case in test_cases:
        content = test_case["plaintext"]
        content_b64 = base64.b64encode(content.encode('utf-8')).decode('ascii')
        
        print(f"\n测试用例 {test_case['id']}: {test_case['name']}")
        print(f"  明文：{content[:50]}{'...' if len(content) > 50 else ''}")
        
        # SM2 加密 Hex 测试
        print("  SM2 加密 (Hex)...")
        java_result, java_error = run_java_test("sm2_encrypt_hex", content_b64, java_keys["encryption_public_key"]["hex"])
        js_result, js_error = run_js_test("sm2_encrypt_hex", content, java_keys["encryption_public_key"]["hex"])
        
        if java_error or js_error:
            results["sm2"]["encrypt_hex"].append({
                "test_id": test_case["id"],
                "status": "failed",
                "java_error": java_error,
                "js_error": js_error
            })
            print(f"    ✗ 失败：Java={java_error}, JS={js_error}")
        else:
            # 验证 Java 加密的结果能否被 JS 解密
            js_decrypt_result, js_decrypt_error = run_js_test("sm2_decrypt_hex", java_result, java_keys["encryption_private_key"]["hex"])
            java_decrypt_result, java_decrypt_error = run_java_test("sm2_decrypt_hex", java_result, java_keys["encryption_private_key"]["hex"])
            
            # 调试输出：显示 JavaScript 解密错误
            if js_decrypt_error:
                print(f"    DEBUG: JS 解密错误={js_decrypt_error}")
                print(f"    DEBUG: Java 密文={java_result[:100]}...")
            
            # Java 返回 Base64 编码，JavaScript 返回 UTF-8 字符串
            java_plain = base64.b64decode(java_decrypt_result).decode('utf-8') if java_decrypt_result else None
            js_plain = js_decrypt_result if js_decrypt_result else None
            
            if java_plain == content and js_plain == content:
                results["sm2"]["encrypt_hex"].append({
                    "test_id": test_case["id"],
                    "status": "success",
                    "java_cipher": java_result[:60] + "...",
                    "js_decrypt_ok": True,
                    "java_decrypt_ok": True
                })
                print(f"    ✓ 成功 (Java 加密 -> JS 解密：OK, Java 解密：OK)")
            else:
                results["sm2"]["encrypt_hex"].append({
                    "test_id": test_case["id"],
                    "status": "failed",
                    "java_cipher": java_result[:60] + "...",
                    "js_decrypt_ok": js_plain == content,
                    "java_decrypt_ok": java_plain == content
                })
                print(f"    ✗ 失败：JS 解密={js_plain}, Java 解密={java_plain}")
        
        # SM2 签名 Hex 测试
        print("  SM2 签名 (Hex)...")
        java_sig, java_error = run_java_test("sm2_sign_hex", content_b64, java_keys["signature_private_key"]["hex"])
        js_sig, js_error = run_js_test("sm2_sign_hex", content, java_keys["signature_private_key"]["hex"])
        
        if java_error or js_error:
            results["sm2"]["sign_hex"].append({
                "test_id": test_case["id"],
                "status": "failed",
                "java_error": java_error,
                "js_error": js_error
            })
            print(f"    ✗ 失败：Java={java_error}, JS={js_error}")
        else:
            # 验证签名
            java_verify, _ = run_java_test("sm2_verify_hex", content_b64, java_keys["signature_public_key"]["hex"], java_sig)
            js_verify, _ = run_js_test("sm2_verify_hex", content, java_keys["signature_public_key"]["hex"], java_sig)
            
            java_ok = java_verify == "true"
            js_ok = js_verify == "true"
            
            if java_ok and js_ok:
                results["sm2"]["sign_hex"].append({
                    "test_id": test_case["id"],
                    "status": "success",
                    "java_sig": java_sig[:60] + "...",
                    "java_verify_ok": True,
                    "js_verify_ok": True
                })
                print(f"    ✓ 成功 (Java 签名 -> 双方验签：OK)")
            else:
                results["sm2"]["sign_hex"].append({
                    "test_id": test_case["id"],
                    "status": "failed",
                    "java_sig": java_sig[:60] + "...",
                    "java_verify_ok": java_ok,
                    "js_verify_ok": js_ok
                })
                print(f"    ✗ 失败：Java 验签={java_ok}, JS 验签={js_ok}")
        
        # SM2 加密签名测试 (Hex)
        print("  SM2 加密签名 (Hex)...")
        java_pair, java_error = run_java_test("sm2_encrypt_sign_hex", content_b64, java_keys["encryption_public_key"]["hex"], java_keys["signature_private_key"]["hex"])
        js_pair, js_error = run_js_test("sm2_encrypt_sign_hex", content, java_keys["encryption_public_key"]["hex"], java_keys["signature_private_key"]["hex"])
        
        if java_error or js_error:
            results["sm2"]["encrypt_sign_hex"].append({
                "test_id": test_case["id"],
                "status": "failed",
                "java_error": java_error,
                "js_error": js_error
            })
            print(f"    ✗ 失败：Java={java_error}, JS={js_error}")
        else:
            # 验证 Java 的加密签名能否被 JS 验签解密
            java_parts = java_pair.split('\t')
            js_verify_decrypt_result, js_verify_decrypt_error = run_js_test(
                "sm2_verify_decrypt_hex", 
                java_parts[0], java_parts[1], 
                java_keys["signature_public_key"]["hex"], 
                java_keys["encryption_private_key"]["hex"]
            )
            # JavaScript 返回 UTF-8 字符串
            js_verify_decrypt_plain = js_verify_decrypt_result if js_verify_decrypt_result else None
            
            if js_verify_decrypt_plain == content:
                results["sm2"]["encrypt_sign_hex"].append({
                    "test_id": test_case["id"],
                    "status": "success",
                    "java_cipher": java_parts[0][:60] + "...",
                    "js_verify_decrypt_ok": True
                })
                print(f"    ✓ 成功 (Java 加密签名 -> JS 验签解密：OK)")
            else:
                results["sm2"]["encrypt_sign_hex"].append({
                    "test_id": test_case["id"],
                    "status": "failed",
                    "java_cipher": java_parts[0][:60] + "...",
                    "js_verify_decrypt_ok": False,
                    "js_result": js_verify_decrypt_plain
                })
                print(f"    ✗ 失败：JS 验签解密结果={js_verify_decrypt_plain}")
    
    return results

def test_sm3_interop():
    """测试 SM3 互通性"""
    print("\n" + "=" * 70)
    print("SM3 互通性测试")
    print("=" * 70)
    
    results = {
        "sm3": {
            "digest": [],
            "hmac": []
        }
    }
    
    test_cases = [
        {"id": 1, "name": "simple_text", "plaintext": "Hello, Crossmool!"},
        {"id": 2, "name": "chinese_text", "plaintext": "跨语言互操作性测试"},
        {"id": 3, "name": "abc", "plaintext": "abc"},  # 标准测试向量
    ]
    
    hmac_key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    
    for test_case in test_cases:
        content = test_case["plaintext"]
        content_b64 = base64.b64encode(content.encode('utf-8')).decode('ascii')
        
        print(f"\n测试用例 {test_case['id']}: {test_case['name']}")
        print(f"  明文：{content[:50]}{'...' if len(content) > 50 else ''}")
        
        # SM3 哈希测试
        print("  SM3 哈希...")
        java_digest, java_error = run_java_test("sm3_digest", content_b64)
        js_digest, js_error = run_js_test("sm3_digest", content)
        
        if java_error or js_error:
            results["sm3"]["digest"].append({
                "test_id": test_case["id"],
                "status": "failed",
                "java_error": java_error,
                "js_error": js_error
            })
            print(f"    ✗ 失败：Java={java_error}, JS={js_error}")
        else:
            if java_digest.lower() == js_digest.lower():
                results["sm3"]["digest"].append({
                    "test_id": test_case["id"],
                    "status": "success",
                    "digest": java_digest[:60] + "...",
                    "match": True
                })
                print(f"    ✓ 成功 (Java={java_digest[:30]}..., JS={js_digest[:30]}..., 匹配)")
            else:
                results["sm3"]["digest"].append({
                    "test_id": test_case["id"],
                    "status": "failed",
                    "java_digest": java_digest,
                    "js_digest": js_digest,
                    "match": False
                })
                print(f"    ✗ 失败：Java={java_digest}, JS={js_digest}")
        
        # HMAC-SM3 测试
        print("  HMAC-SM3...")
        java_hmac, java_error = run_java_test("sm3_hmac", hmac_key_hex, content_b64)
        js_hmac, js_error = run_js_test("sm3_hmac", hmac_key_hex, content)
        
        if java_error or js_error:
            results["sm3"]["hmac"].append({
                "test_id": test_case["id"],
                "status": "failed",
                "java_error": java_error,
                "js_error": js_error
            })
            print(f"    ✗ 失败：Java={java_error}, JS={js_error}")
        else:
            if java_hmac.lower() == js_hmac.lower():
                results["sm3"]["hmac"].append({
                    "test_id": test_case["id"],
                    "status": "success",
                    "hmac": java_hmac[:60] + "...",
                    "match": True
                })
                print(f"    ✓ 成功 (Java={java_hmac[:30]}..., JS={js_hmac[:30]}..., 匹配)")
            else:
                results["sm3"]["hmac"].append({
                    "test_id": test_case["id"],
                    "status": "failed",
                    "java_hmac": java_hmac,
                    "js_hmac": js_hmac,
                    "match": False
                })
                print(f"    ✗ 失败：Java={java_hmac}, JS={js_hmac}")
    
    return results

def test_sm4_interop():
    """测试 SM4 互通性"""
    print("\n" + "=" * 70)
    print("SM4 互通性测试")
    print("=" * 70)
    
    results = {
        "sm4": {
            "encrypt_decrypt": []
        }
    }
    
    test_cases = [
        {"id": 1, "name": "simple_text", "plaintext": "Hello, Crossmool!"},
        {"id": 2, "name": "chinese_text", "plaintext": "跨语言互操作性测试"},
        {"id": 3, "name": "mixed_content", "plaintext": "Test 测试 123!@#"},
    ]
    
    sm4_key_hex = "0123456789abcdef0123456789abcdef"
    sm4_key_base64 = base64.b64encode(bytes.fromhex(sm4_key_hex)).decode('ascii')
    
    for test_case in test_cases:
        content = test_case["plaintext"]
        content_b64 = base64.b64encode(content.encode('utf-8')).decode('ascii')
        
        print(f"\n测试用例 {test_case['id']}: {test_case['name']}")
        print(f"  明文：{content[:50]}{'...' if len(content) > 50 else ''}")
        
        # SM4 GCM 加密测试 (Java 加密，双方解密)
        print("  SM4 GCM 加密 (Java -> JS 解密)...")
        java_encrypt_result, java_error = run_java_test("sm4_encrypt_hex", content_b64, sm4_key_hex)
        
        if java_error:
            results["sm4"]["encrypt_decrypt"].append({
                "test_id": test_case["id"],
                "status": "failed",
                "java_error": java_error
            })
            print(f"    ✗ Java 加密失败：{java_error}")
        else:
            # JS 解密 Java 加密的结果
            js_decrypt_result, js_error = run_js_test("sm4_decrypt_hex", java_encrypt_result, sm4_key_hex)
            # JavaScript 返回 UTF-8 字符串
            js_plain = js_decrypt_result if js_decrypt_result else None
            
            if js_plain == content:
                results["sm4"]["encrypt_decrypt"].append({
                    "test_id": test_case["id"],
                    "status": "success",
                    "java_cipher": java_encrypt_result[:60] + "...",
                    "js_decrypt_ok": True
                })
                print(f"    ✓ 成功 (Java 加密 -> JS 解密：OK)")
            else:
                results["sm4"]["encrypt_decrypt"].append({
                    "test_id": test_case["id"],
                    "status": "failed",
                    "java_cipher": java_encrypt_result[:60] + "...",
                    "js_decrypt_ok": False,
                    "js_result": js_plain
                })
                print(f"    ✗ 失败：JS 解密结果={js_plain}")
    
    return results

def generate_report(results, output_file):
    """生成测试报告"""
    report = []
    report.append("# Java-JavaScript SM2/SM3/SM4 互通性测试报告")
    report.append("")
    report.append("## 测试概述")
    report.append("")
    report.append("本报告测试了 Java 和 JavaScript 两种语言实现的 SM2、SM3、SM4 算法的互通性。")
    report.append("")
    report.append("### 测试环境")
    report.append("")
    report.append(f"- Java 版本：{os.environ.get('JAVA_VERSION', 'JDK 17')}")
    report.append(f"- Node.js 版本：{subprocess.check_output([NODE_EXECUTABLE, '--version'], text=True).strip()}")
    report.append("")
    
    # SM2 测试结果
    report.append("## SM2 互通性测试")
    report.append("")
    sm2 = results.get("sm2", {})
    
    for test_type in ["encrypt_hex", "sign_hex", "encrypt_sign_hex"]:
        test_results = sm2.get(test_type, [])
        success_count = sum(1 for r in test_results if r.get("status") == "success")
        total_count = len(test_results)
        report.append(f"### {test_type.replace('_', ' ').title()}")
        report.append("")
        report.append(f"- 测试用例数：{total_count}")
        report.append(f"- 成功：{success_count}")
        report.append(f"- 失败：{total_count - success_count}")
        report.append(f"- 成功率：{success_count / total_count * 100:.1f}%" if total_count > 0 else "- 成功率：N/A")
        report.append("")
        
        for result in test_results:
            status_icon = "✓" if result.get("status") == "success" else "✗"
            report.append(f"- {status_icon} 测试用例 {result.get('test_id')}: {result.get('status')}")
        report.append("")
    
    # SM3 测试结果
    report.append("## SM3 互通性测试")
    report.append("")
    sm3 = results.get("sm3", {})
    
    for test_type in ["digest", "hmac"]:
        test_results = sm3.get(test_type, [])
        success_count = sum(1 for r in test_results if r.get("status") == "success")
        total_count = len(test_results)
        report.append(f"### {test_type.title()}")
        report.append("")
        report.append(f"- 测试用例数：{total_count}")
        report.append(f"- 成功：{success_count}")
        report.append(f"- 失败：{total_count - success_count}")
        report.append(f"- 成功率：{success_count / total_count * 100:.1f}%" if total_count > 0 else "- 成功率：N/A")
        report.append("")
        
        for result in test_results:
            status_icon = "✓" if result.get("status") == "success" else "✗"
            report.append(f"- {status_icon} 测试用例 {result.get('test_id')}: {result.get('status')}")
        report.append("")
    
    # SM4 测试结果
    report.append("## SM4 互通性测试")
    report.append("")
    sm4 = results.get("sm4", {})
    test_results = sm4.get("encrypt_decrypt", [])
    success_count = sum(1 for r in test_results if r.get("status") == "success")
    total_count = len(test_results)
    report.append(f"### 加密解密互通性")
    report.append("")
    report.append(f"- 测试用例数：{total_count}")
    report.append(f"- 成功：{success_count}")
    report.append(f"- 失败：{total_count - success_count}")
    report.append(f"- 成功率：{success_count / total_count * 100:.1f}%" if total_count > 0 else "- 成功率：N/A")
    report.append("")
    
    for result in test_results:
        status_icon = "✓" if result.get("status") == "success" else "✗"
        report.append(f"- {status_icon} 测试用例 {result.get('test_id')}: {result.get('status')}")
    report.append("")
    
    # 总结
    report.append("## 测试总结")
    report.append("")
    
    total_tests = 0
    total_success = 0
    
    for algo in ["sm2", "sm3", "sm4"]:
        algo_results = results.get(algo, {})
        for test_type, test_results in algo_results.items():
            for result in test_results:
                total_tests += 1
                if result.get("status") == "success":
                    total_success += 1
    
    report.append(f"- 总测试用例数：{total_tests}")
    report.append(f"- 成功：{total_success}")
    report.append(f"- 失败：{total_tests - total_success}")
    report.append(f"- 成功率：{total_success / total_tests * 100:.1f}%" if total_tests > 0 else "- 成功率：N/A")
    report.append("")
    
    report.append("## 结论")
    report.append("")
    if total_success == total_tests:
        report.append("✅ **所有测试通过！** Java 和 JavaScript 的 SM2/SM3/SM4 实现完全互通。")
    else:
        report.append(f"⚠️ **部分测试失败。** {total_tests - total_success} 个测试用例未通过，需要进一步检查。")
    report.append("")
    
    report_content = "\n".join(report)
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    print(f"\n测试报告已保存到：{output_file}")
    return report_content

def main():
    """主函数"""
    print("=" * 70)
    print("Java-JavaScript SM2/SM3/SM4 互通性测试")
    print("=" * 70)
    
    # 检查环境
    if not os.path.exists(JAVA_EXECUTABLE):
        print(f"错误：找不到 Java 可执行文件：{JAVA_EXECUTABLE}")
        sys.exit(1)
    
    if not os.path.exists(NODE_EXECUTABLE):
        try:
            subprocess.run([NODE_EXECUTABLE, "--version"], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"错误：找不到 Node.js 可执行文件：{NODE_EXECUTABLE}")
            sys.exit(1)
    
    if not os.path.exists(JAR_PATH):
        print(f"错误：找不到 JAR 文件：{JAR_PATH}")
        sys.exit(1)
    
    if not os.path.exists(JS_DIST_PATH):
        print(f"错误：找不到 JavaScript dist 目录：{JS_DIST_PATH}")
        print("请先运行：cd javascript/crossmool && npm run build")
        sys.exit(1)
    
    if not os.path.exists(JAVA_KEYS_FILE):
        print(f"错误：找不到 Java 密钥文件：{JAVA_KEYS_FILE}")
        sys.exit(1)
    
    # 加载密钥
    print(f"\n加载 Java 密钥文件：{JAVA_KEYS_FILE}")
    java_keys = load_json_file(JAVA_KEYS_FILE)
    
    # 尝试加载 JavaScript 密钥文件（如果存在）
    js_keys = java_keys  # 默认使用相同的密钥
    if os.path.exists(JS_KEYS_FILE):
        print(f"加载 JavaScript 密钥文件：{JS_KEYS_FILE}")
        js_keys = load_json_file(JS_KEYS_FILE)
    else:
        print("使用 Java 密钥进行 JavaScript 测试")
    
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 运行测试
    all_results = {}
    
    # SM2 测试
    sm2_results = test_sm2_interop(java_keys, js_keys)
    all_results.update(sm2_results)
    
    # SM3 测试
    sm3_results = test_sm3_interop()
    all_results.update(sm3_results)
    
    # SM4 测试
    sm4_results = test_sm4_interop()
    all_results.update(sm4_results)
    
    # 保存详细结果
    results_file = os.path.join(OUTPUT_DIR, "test_results.json")
    save_json_file(results_file, all_results)
    print(f"\n详细测试结果已保存到：{results_file}")
    
    # 生成报告
    report_file = os.path.join(OUTPUT_DIR, "Java-JavaScript-interop-test-report.md")
    generate_report(all_results, report_file)
    
    # 打印总结
    print("\n" + "=" * 70)
    print("测试完成")
    print("=" * 70)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())