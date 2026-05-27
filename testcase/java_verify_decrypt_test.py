#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Java SM2 解密验签互操作性测试脚本

验证其他语言加密签名的数据，Java能否正确验签解密。
"""

import json
import os
import sys
import subprocess
import base64
from pathlib import Path

JDK_HOME = r"D:\Programs\Java\jdk-17.0.9+9"
JAVA_EXECUTABLE = os.path.join(JDK_HOME, "bin", "java.exe")
JAR_PATH = "java/crossmool/target/crossmool-1.1.0.jar"
CLASSPATH_FILE = "java/crossmool/classpath.txt"
KEYS_DIR = "testcase/keys"
TEMP_DIR = "testcase/.java_verify_temp"

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

def get_keys_for_language(language):
    keys_file = os.path.join(KEYS_DIR, language, "keys.json")
    if not os.path.exists(keys_file):
        return None
    keys = load_json_file(keys_file)
    if "signature_public_key" not in keys or "encryption_private_key" not in keys:
        return None
    return {
        "sign_public_key_hex": keys["signature_public_key"]["hex"],
        "dec_private_key_hex": keys["encryption_private_key"]["hex"],
    }

def ensure_java_verify_class():
    """Ensure the SM2VerifyDecryptTest.java is compiled and ready."""
    test_class_dir = "testcase/java_test_classes"
    os.makedirs(test_class_dir, exist_ok=True)
    
    class_file = os.path.join(test_class_dir, "testcase", "SM2VerifyDecryptTest.class")
    if os.path.exists(class_file):
        return test_class_dir
    
    java_class_file = os.path.join(test_class_dir, "SM2VerifyDecryptTest.java")
    java_code = '''package testcase;

import cc.iili.tools.crossmool.tool.SM2Util;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class SM2VerifyDecryptTest {
    public static void main(String[] args) throws Exception {
        String inputFile = args[0];
        String inputJson = new String(Files.readAllBytes(Paths.get(inputFile)), "UTF-8");
        
        String ciphertextHex = extractField(inputJson, "ciphertext_hex");
        String signatureHex = extractField(inputJson, "signature_hex");
        String signPublicKey = extractField(inputJson, "sign_public_key_hex");
        String decPrivateKey = extractField(inputJson, "dec_private_key_hex");
        
        String decrypted = SM2Util.verifyDecrypt(ciphertextHex, signatureHex, signPublicKey, decPrivateKey);
        String b64 = Base64.getEncoder().encodeToString(decrypted.getBytes("UTF-8"));
        System.out.println("SUCCESS:" + b64);
    }
    
    static String extractField(String json, String key) {
        int idx = json.indexOf("\\\"" + key + "\\\"");
        if (idx < 0) throw new RuntimeException("Field not found: " + key);
        int colon = json.indexOf(':', idx);
        int openQuote = json.indexOf('"', colon);
        int closeQuote = openQuote + 1;
        while (closeQuote < json.length()) {
            if (json.charAt(closeQuote) == '"' && json.charAt(closeQuote - 1) != '\\\\') break;
            if (json.charAt(closeQuote) == '"' && json.charAt(closeQuote - 1) == '\\\\' && json.charAt(closeQuote - 2) == '\\\\') break;
            closeQuote++;
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

def run_java_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    test_class_dir = ensure_java_verify_class()
    full_cp = f"{test_class_dir};{get_full_classpath()}"
    
    temp_path = Path(TEMP_DIR)
    temp_path.mkdir(exist_ok=True)
    
    input_file = temp_path / "input_data.json"
    input_data = {
        "ciphertext_hex": ciphertext_hex,
        "signature_hex": signature_hex,
        "sign_public_key_hex": sign_public_key_hex,
        "dec_private_key_hex": dec_private_key_hex
    }
    input_file.write_text(json.dumps(input_data, ensure_ascii=False), encoding='utf-8')
    
    try:
        run_result = subprocess.run(
            [JAVA_EXECUTABLE, "-cp", full_cp, "testcase.SM2VerifyDecryptTest", str(input_file)],
            capture_output=True, text=True, timeout=30
        )
        
        if run_result.returncode != 0:
            error_msg = run_result.stderr.strip()
            if "ERROR:" in error_msg:
                error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
            return False, error_msg
        
        output = run_result.stdout.strip()
        if output.startswith("SUCCESS:"):
            b64_text = output[8:]
            decrypted_text = base64.b64decode(b64_text).decode('utf-8')
            return True, decrypted_text
        else:
            return False, f"unknown output: {output}"
    
    except subprocess.TimeoutExpired:
        return False, "Java program timeout"
    except Exception as e:
        return False, f"Java program exception: {e}"

def verify_language_results(language, output_dir):
    results = []
    success_count = 0
    fail_count = 0
    
    keys = get_keys_for_language(language)
    if keys is None:
        print(f"\n  warn: missing required keys for language: {language}, skipping")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    sign_public_key_hex = keys["sign_public_key_hex"]
    dec_private_key_hex = keys["dec_private_key_hex"]
    
    if not os.path.exists(output_dir):
        print(f"\n  warn: encrypt result dir not found: {output_dir}")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    json_files = sorted(Path(output_dir).glob("test_*.json"))
    
    if not json_files:
        print(f"\n  warn: no test case files in {output_dir}")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    print(f"\n  found {len(json_files)} encrypt result files")
    print(f"  using keys from: {language}")
    
    for json_file in json_files:
        if json_file.name.startswith("summary"):
            continue
        
        try:
            result_data = load_json_file(str(json_file))
            test_id = result_data.get("test_case_id", "unknown")
            test_name = result_data.get("test_case_name", "unknown")
            expected_plaintext = result_data.get("plaintext", "")
            ciphertext_hex = result_data.get("ciphertext_hex", "")
            signature_hex = result_data.get("signature_hex", "")
            
            print(f"\n  test case {test_id}: {test_name}")
            print(f"    source language: {language}")
            
            success, decrypted_or_error = run_java_verify_decrypt(
                ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex
            )
            
            if success:
                if decrypted_or_error == expected_plaintext:
                    print(f"    [OK] verify success, decrypt result matches")
                    success_count += 1
                    result_entry = {
                        "test_case_id": test_id,
                        "test_case_name": test_name,
                        "source_language": language,
                        "status": "success",
                        "expected_plaintext": expected_plaintext,
                        "decrypted_text": decrypted_or_error,
                        "match": True
                    }
                else:
                    print(f"    [FAIL] verify success, but decrypt result mismatch")
                    print(f"    expected: {repr(expected_plaintext[:50])}")
                    print(f"    actual: {repr(decrypted_or_error[:50])}")
                    fail_count += 1
                    result_entry = {
                        "test_case_id": test_id,
                        "test_case_name": test_name,
                        "source_language": language,
                        "status": "mismatch",
                        "expected_plaintext": expected_plaintext,
                        "decrypted_text": decrypted_or_error,
                        "match": False
                    }
            else:
                print(f"    [FAIL] verify failed: {decrypted_or_error}")
                fail_count += 1
                result_entry = {
                    "test_case_id": test_id,
                    "test_case_name": test_name,
                    "source_language": language,
                    "status": "failed",
                    "error": decrypted_or_error,
                    "expected_plaintext": expected_plaintext,
                    "match": False
                }
            
            results.append(result_entry)
        
        except Exception as e:
            print(f"\n  error processing file {json_file.name}: {e}")
            fail_count += 1
    
    return {
        "total": len(json_files),
        "success": success_count,
        "failed": fail_count,
        "results": results
    }

def main():
    print("=" * 70)
    print("Java SM2 Verify-Decrypt Interop Test")
    print("=" * 70)
    
    OUTPUT_DIR = "testcase/results/java_verify"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    languages = [
        ("c", "testcase/results/c_encrypt"),
        ("cpp", "testcase/results/cpp_encrypt"),
        ("csharp", "testcase/results/csharp_encrypt"),
        ("golang", "testcase/results/golang_encrypt"),
        ("java", "testcase/results/java_encrypt"),
        ("javascript", "testcase/results/javascript_encrypt"),
        ("python", "testcase/results/python_encrypt"),
        ("rust", "testcase/results/rust_encrypt"),
    ]
    
    all_results = {}
    total_tests = 0
    total_success = 0
    total_failed = 0
    
    for language, encrypt_dir in languages:
        print(f"\n{'=' * 70}")
        print(f"Verifying {language.upper()} encrypt results with Java")
        print(f"{'=' * 70}")
        
        lang_result = verify_language_results(language, encrypt_dir)
        all_results[language] = lang_result
        
        total_tests += lang_result["total"]
        total_success += lang_result["success"]
        total_failed += lang_result["failed"]
        
        if lang_result["total"] > 0:
            lang_output_file = os.path.join(OUTPUT_DIR, f"{language}_verify_summary.json")
            save_json_file(lang_output_file, lang_result)
            print(f"\n  {language} verify result saved to: {lang_output_file}")
            print(f"  total: {lang_result['total']}, success: {lang_result['success']}, failed: {lang_result['failed']}")
    
    summary_data = {
        "summary": {
            "total": total_tests,
            "success": total_success,
            "failed": total_failed,
            "success_rate": f"{total_success / total_tests * 100:.1f}%" if total_tests > 0 else "0%"
        },
        "languages": all_results
    }
    
    summary_file = os.path.join(OUTPUT_DIR, "summary.json")
    save_json_file(summary_file, summary_data)
    print(f"\nsummary saved to: {summary_file}")
    
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Total test cases: {total_tests}")
    print(f"Success: {total_success}")
    print(f"Failed: {total_failed}")
    if total_tests > 0:
        print(f"Success rate: {total_success / total_tests * 100:.1f}%")
    print("=" * 70)
    
    return 0 if total_failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
