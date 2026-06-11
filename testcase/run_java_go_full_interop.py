#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java-Go SM2/SM3/SM4 互通性测试脚本
测试 Hex 和 Base64 两种编码格式的互通性
"""

import subprocess
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# 配置路径
WORKSPACE = Path(__file__).parent.parent
JAVA_DIR = WORKSPACE / "java" / "crossmool"
GO_DIR = WORKSPACE / "golang" / "crossmool"
TESTCASE_DIR = WORKSPACE / "testcase"

# 测试数据
TEST_PLAINTEXT = "Hello, 这是国密 SM2/SM3/SM4 互通性测试数据"
TEST_PLAINTEXT_BYTES = TEST_PLAINTEXT.encode('utf-8')

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.details = []
    
    def add_pass(self, name, detail=""):
        self.passed += 1
        self.details.append({"name": name, "status": "PASS", "detail": detail})
        print(f"  [PASS] {name}")
    
    def add_fail(self, name, error):
        self.failed += 1
        self.details.append({"name": name, "status": "FAIL", "error": str(error)})
        print(f"  [FAIL] {name}: {error}")
    
    def summary(self):
        return {"passed": self.passed, "failed": self.failed, "details": self.details}

def run_java_generate_test_data():
    """运行 Java 生成测试数据"""
    print("\n[1/6] Java 生成测试数据...")
    try:
        result = subprocess.run(
            ["java", "-cp", "target/classes", 
             "cc.iili.tools.crossmool.tool.SM4Util"],
            cwd=JAVA_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        print("  Java SM4Util 自测完成")
        return True
    except Exception as e:
        print(f"  Java 测试失败：{e}")
        return False

def run_go_tests():
    """运行 Go 单元测试"""
    print("\n[2/6] Go 运行单元测试...")
    try:
        result = subprocess.run(
            ["go", "test", "-v", "-run", "SM4|SM2|SM3"],
            cwd=GO_DIR,
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.returncode == 0:
            print("  Go 单元测试全部通过")
            return True
        else:
            print(f"  Go 测试失败：{result.stderr}")
            return False
    except Exception as e:
        print(f"  Go 测试异常：{e}")
        return False

def test_sm4_java_to_go():
    """SM4 Java→Go 互通测试"""
    print("\n[3/6] SM4 Java→Go 互通测试...")
    result = TestResult()
    
    # 使用固定密钥和明文进行加密
    java_key_hex = "0123456789abcdeffedcba9876543210"
    java_plain = "Hello SM4"
    
    # Java 加密（Hex 输出）
    try:
        # 创建临时 Java 测试类
        test_code = '''
package cc.iili.tools.crossmool.test;
import cc.iili.tools.crossmool.tool.SM4Util;
public class SM4JavaToGoTest {
    public static void main(String[] args) {
        String key = "0123456789abcdeffedcba9876543210";
        String plain = "Hello SM4";
        
        // Hex 加密
        String encHex = SM4Util.encrypt(key, plain, false);
        System.out.println("JAVA_SM4_HEX_KEY=" + key);
        System.out.println("JAVA_SM4_HEX_PLAIN=" + plain);
        System.out.println("JAVA_SM4_HEX_CIPHER=" + encHex);
        
        // Base64 加密
        String encBase64 = SM4Util.encrypt(key, plain, true);
        System.out.println("JAVA_SM4_B64_CIPHER=" + encBase64);
    }
}
'''
        test_file = TESTCASE_DIR / "SM4JavaToGoTest.java"
        test_file.write_text(test_code)
        
        # 编译
        subprocess.run(
            ["javac", "-cp", "target/classes", "-d", "target/classes", str(test_file)],
            cwd=JAVA_DIR,
            check=True,
            capture_output=True
        )
        
        # 运行
        proc = subprocess.run(
            ["java", "-cp", "target/classes", "cc.iili.tools.crossmool.test.SM4JavaToGoTest"],
            cwd=JAVA_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        java_data = {}
        for line in proc.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                java_data[k] = v
        
        print(f"  Java Hex 密文：{java_data.get('JAVA_SM4_HEX_CIPHER', 'N/A')[:50]}...")
        print(f"  Java Base64 密文：{java_data.get('JAVA_SM4_B64_CIPHER', 'N/A')[:50]}...")
        
        # Go 解密验证
        go_verify_code = f'''
package main
import (
    "fmt"
    "cc.iili.tools/crossmool"
)
func main() {{
    key, _ := crossmool.DecodeHexString("{java_key_hex}")
    hexCipher := "{java_data.get('JAVA_SM4_HEX_CIPHER', '')}"
    b64Cipher := "{java_data.get('JAVA_SM4_B64_CIPHER', '')}"
    
    // 解密 Hex
    if hexCipher != "" {{
        plain, err := crossmool.DecryptGcmToString(key, hexCipher)
        if err != nil {{
            fmt.Printf("Go 解密 Hex 失败：%v\\n", err)
        }} else {{
            fmt.Printf("GO_SM4_HEX_DEC=%s\\n", plain)
        }}
    }}
    
    // 解密 Base64
    if b64Cipher != "" {{
        plain, err := crossmool.DecryptGcmToString(key, b64Cipher)
        if err != nil {{
            fmt.Printf("Go 解密 Base64 失败：%v\\n", err)
        }} else {{
            fmt.Printf("GO_SM4_B64_DEC=%s\\n", plain)
        }}
    }}
}}
'''
        go_test_file = TESTCASE_DIR / "sm4_go_verify.go"
        go_test_file.write_text(go_verify_code)
        
        go_result = subprocess.run(
            ["go", "run", str(go_test_file)],
            cwd=GO_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        go_decrypted = {}
        for line in go_result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                go_decrypted[k] = v
        
        # 验证结果
        if go_decrypted.get('GO_SM4_HEX_DEC') == java_plain:
            result.add_pass("SM4 Java→Go Hex 解密")
        else:
            result.add_fail("SM4 Java→Go Hex 解密", f"期望'{java_plain}', 得到'{go_decrypted.get('GO_SM4_HEX_DEC')}'")
        
        if go_decrypted.get('GO_SM4_B64_DEC') == java_plain:
            result.add_pass("SM4 Java→Go Base64 解密")
        else:
            result.add_fail("SM4 Java→Go Base64 解密", f"期望'{java_plain}', 得到'{go_decrypted.get('GO_SM4_B64_DEC')}'")
        
    except Exception as e:
        result.add_fail("SM4 Java→Go 测试", str(e))
    
    return result.summary()

def test_sm4_go_to_java():
    """SM4 Go→Java 互通测试"""
    print("\n[4/6] SM4 Go→Java 互通测试...")
    result = TestResult()
    
    go_key_hex = "0123456789abcdeffedcba9876543210"
    go_plain = "Hello SM4 from Go"
    
    try:
        # Go 加密
        go_encrypt_code = f'''
package main
import (
    "fmt"
    "cc.iili.tools/crossmool"
)
func main() {{
    key, _ := crossmool.DecodeHexString("{go_key_hex}")
    plain := []byte("{go_plain}")
    
    // Hex 加密
    encHex, _ := crossmool.EncryptGcm(key, plain, false)
    fmt.Printf("GO_SM4_HEX_KEY={key}\\n")
    fmt.Printf("GO_SM4_HEX_PLAIN={go_plain}\\n")
    fmt.Printf("GO_SM4_HEX_CIPHER=%s\\n", encHex)
    
    // Base64 加密
    encB64, _ := crossmool.EncryptGcm(key, plain, true)
    fmt.Printf("GO_SM4_B64_CIPHER=%s\\n", encB64)
}}
'''
        go_test_file = TESTCASE_DIR / "sm4_go_encrypt.go"
        go_test_file.write_text(go_encrypt_code)
        
        go_result = subprocess.run(
            ["go", "run", str(go_test_file)],
            cwd=GO_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        go_data = {}
        for line in go_result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                go_data[k] = v
        
        print(f"  Go Hex 密文：{go_data.get('GO_SM4_HEX_CIPHER', 'N/A')[:50]}...")
        print(f"  Go Base64 密文：{go_data.get('GO_SM4_B64_CIPHER', 'N/A')[:50]}...")
        
        # Java 解密验证
        java_verify_code = f'''
package cc.iili.tools.crossmool.test;
import cc.iili.tools.crossmool.tool.SM4Util;
public class SM4GoToJavaTest {{
    public static void main(String[] args) {{
        String key = "{go_key_hex}";
        String hexCipher = "{go_data.get('GO_SM4_HEX_CIPHER', '')}";
        String b64Cipher = "{go_data.get('GO_SM4_B64_CIPHER', '')}";
        String expected = "{go_plain}";
        
        try {{
            String decHex = SM4Util.decrypt(key, hexCipher);
            System.out.println("JAVA_SM4_HEX_DEC=" + decHex);
        }} catch (Exception e) {{
            System.out.println("JAVA_SM4_HEX_DEC=ERROR:" + e.getMessage());
        }}
        
        try {{
            String decB64 = SM4Util.decrypt(key, b64Cipher);
            System.out.println("JAVA_SM4_B64_DEC=" + decB64);
        }} catch (Exception e) {{
            System.out.println("JAVA_SM4_B64_DEC=ERROR:" + e.getMessage());
        }}
    }}
}}
'''
        java_test_file = TESTCASE_DIR / "SM4GoToJavaTest.java"
        java_test_file.write_text(java_verify_code)
        
        subprocess.run(
            ["javac", "-cp", "target/classes", "-d", "target/classes", str(java_test_file)],
            cwd=JAVA_DIR,
            check=True,
            capture_output=True
        )
        
        java_result = subprocess.run(
            ["java", "-cp", "target/classes", "cc.iili.tools.crossmool.test.SM4GoToJavaTest"],
            cwd=JAVA_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        java_decrypted = {}
        for line in java_result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                java_decrypted[k] = v
        
        if java_decrypted.get('JAVA_SM4_HEX_DEC') == go_plain:
            result.add_pass("SM4 Go→Java Hex 解密")
        else:
            result.add_fail("SM4 Go→Java Hex 解密", f"期望'{go_plain}', 得到'{java_decrypted.get('JAVA_SM4_HEX_DEC')}'")
        
        if java_decrypted.get('JAVA_SM4_B64_DEC') == go_plain:
            result.add_pass("SM4 Go→Java Base64 解密")
        else:
            result.add_fail("SM4 Go→Java Base64 解密", f"期望'{go_plain}', 得到'{java_decrypted.get('JAVA_SM4_B64_DEC')}'")
        
    except Exception as e:
        result.add_fail("SM4 Go→Java 测试", str(e))
    
    return result.summary()

def test_sm2_java_go():
    """SM2 Java↔Go 互通测试"""
    print("\n[5/6] SM2 Java↔Go 互通测试...")
    result = TestResult()
    
    # 简单测试：使用 Go 生成密钥对，Java 加密，Go 解密
    try:
        # Go 生成密钥对
        go_keygen_code = '''
package main
import (
    "fmt"
    "cc.iili.tools/crossmool"
)
func main() {
    pubHex, privHex, err := crossmool.GenerateKeyPairHex()
    if err != nil {
        fmt.Printf("ERROR=%v\\n", err)
        return
    }
    fmt.Printf("GO_SM2_PUB_HEX=%s\\n", pubHex)
    fmt.Printf("GO_SM2_PRIV_HEX=%s\\n", privHex)
}
'''
        go_test_file = TESTCASE_DIR / "sm2_go_keygen.go"
        go_test_file.write_text(go_keygen_code)
        
        go_result = subprocess.run(
            ["go", "run", str(go_test_file)],
            cwd=GO_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        go_keys = {}
        for line in go_result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                go_keys[k] = v
        
        if 'ERROR' in go_keys:
            result.add_fail("SM2 Go 密钥生成", go_keys['ERROR'])
            return result.summary()
        
        pub_hex = go_keys.get('GO_SM2_PUB_HEX', '')
        priv_hex = go_keys.get('GO_SM2_PRIV_HEX', '')
        
        print(f"  Go 生成公钥：{pub_hex[:50]}...")
        
        # Java 加密
        java_encrypt_code = f'''
package cc.iili.tools.crossmool.test;
import cc.iili.tools.crossmool.tool.SM2Util;
public class SM2JavaEncrypt {{
    public static void main(String[] args) {{
        String pubKey = "{pub_hex}";
        String plain = "Hello SM2";
        
        try {{
            String cipherHex = SM2Util.encrypt(plain, pubKey, false);
            System.out.println("JAVA_SM2_CIPHER_HEX=" + cipherHex);
            
            String cipherB64 = SM2Util.encrypt(plain, pubKey, true);
            System.out.println("JAVA_SM2_CIPHER_B64=" + cipherB64);
        }} catch (Exception e) {{
            System.out.println("JAVA_SM2_ERROR=" + e.getMessage());
        }}
    }}
}}
'''
        java_test_file = TESTCASE_DIR / "SM2JavaEncrypt.java"
        java_test_file.write_text(java_encrypt_code)
        
        subprocess.run(
            ["javac", "-cp", "target/classes", "-d", "target/classes", str(java_test_file)],
            cwd=JAVA_DIR,
            check=True,
            capture_output=True
        )
        
        java_result = subprocess.run(
            ["java", "-cp", "target/classes", "cc.iili.tools.crossmool.test.SM2JavaEncrypt"],
            cwd=JAVA_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        java_cipher = {}
        for line in java_result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                java_cipher[k] = v
        
        if 'JAVA_SM2_ERROR' in java_cipher:
            result.add_fail("SM2 Java 加密", java_cipher['JAVA_SM2_ERROR'])
            return result.summary()
        
        # Go 解密
        go_decrypt_code = f'''
package main
import (
    "fmt"
    "cc.iili.tools/crossmool"
)
func main() {{
    privKey := "{priv_hex}"
    cipherHex := "{java_cipher.get('JAVA_SM2_CIPHER_HEX', '')}"
    cipherB64 := "{java_cipher.get('JAVA_SM2_CIPHER_B64', '')}"
    
    if cipherHex != "" {{
        plain, err := crossmool.Decrypt(cipherHex, privKey)
        if err != nil {{
            fmt.Printf("GO_SM2_HEX_DEC=ERROR:%v\\n", err)
        }} else {{
            fmt.Printf("GO_SM2_HEX_DEC=%s\\n", plain)
        }}
    }}
    
    if cipherB64 != "" {{
        plain, err := crossmool.Decrypt(cipherB64, privKey)
        if err != nil {{
            fmt.Printf("GO_SM2_B64_DEC=ERROR:%v\\n", err)
        }} else {{
            fmt.Printf("GO_SM2_B64_DEC=%s\\n", plain)
        }}
    }}
}}
'''
        go_test_file = TESTCASE_DIR / "sm2_go_decrypt.go"
        go_test_file.write_text(go_decrypt_code)
        
        go_result = subprocess.run(
            ["go", "run", str(go_test_file)],
            cwd=GO_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        go_decrypted = {}
        for line in go_result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                go_decrypted[k] = v
        
        if "Hello SM2" in go_decrypted.get('GO_SM2_HEX_DEC', ''):
            result.add_pass("SM2 Java→Go Hex 解密")
        else:
            result.add_fail("SM2 Java→Go Hex 解密", go_decrypted.get('GO_SM2_HEX_DEC', 'N/A'))
        
        if "Hello SM2" in go_decrypted.get('GO_SM2_B64_DEC', ''):
            result.add_pass("SM2 Java→Go Base64 解密")
        else:
            result.add_fail("SM2 Java→Go Base64 解密", go_decrypted.get('GO_SM2_B64_DEC', 'N/A'))
        
    except Exception as e:
        result.add_fail("SM2 Java↔Go 测试", str(e))
    
    return result.summary()

def test_sm3_java_go():
    """SM3 Java↔Go 互通测试"""
    print("\n[6/6] SM3 Java↔Go 互通测试...")
    result = TestResult()
    
    test_data = "Hello SM3 互通性测试"
    
    try:
        # Java 计算 SM3
        java_sm3_code = f'''
package cc.iili.tools.crossmool.test;
import cc.iili.tools.crossmool.tool.SM3Util;
public class SM3JavaTest {{
    public static void main(String[] args) {{
        String data = "{test_data}";
        
        String digestHex = SM3Util.digestHex(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        System.out.println("JAVA_SM3_HEX=" + digestHex);
        
        String digestB64 = SM3Util.digestBase64(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        System.out.println("JAVA_SM3_B64=" + digestB64);
    }}
}}
'''
        java_test_file = TESTCASE_DIR / "SM3JavaTest.java"
        java_test_file.write_text(java_sm3_code)
        
        subprocess.run(
            ["javac", "-cp", "target/classes", "-d", "target/classes", str(java_test_file)],
            cwd=JAVA_DIR,
            check=True,
            capture_output=True
        )
        
        java_result = subprocess.run(
            ["java", "-cp", "target/classes", "cc.iili.tools.crossmool.test.SM3JavaTest"],
            cwd=JAVA_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        java_digest = {}
        for line in java_result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                java_digest[k] = v
        
        # Go 计算 SM3
        go_sm3_code = f'''
package main
import (
    "fmt"
    "cc.iili.tools/crossmool"
)
func main() {{
    data := []byte("{test_data}")
    
    digestHex := crossmool.DigestHex(data)
    fmt.Printf("GO_SM3_HEX=%s\\n", digestHex)
    
    digestB64 := crossmool.DigestBase64(data)
    fmt.Printf("GO_SM3_B64=%s\\n", digestB64)
}}
'''
        go_test_file = TESTCASE_DIR / "sm3_go_test.go"
        go_test_file.write_text(go_sm3_code)
        
        go_result = subprocess.run(
            ["go", "run", str(go_test_file)],
            cwd=GO_DIR,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        go_digest = {}
        for line in go_result.stdout.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                go_digest[k] = v
        
        # 比较结果
        if java_digest.get('JAVA_SM3_HEX') == go_digest.get('GO_SM3_HEX'):
            result.add_pass("SM3 Hex 摘要一致")
        else:
            result.add_fail("SM3 Hex 摘要一致", 
                f"Java: {java_digest.get('JAVA_SM3_HEX', 'N/A')}, Go: {go_digest.get('GO_SM3_HEX', 'N/A')}")
        
        if java_digest.get('JAVA_SM3_B64') == go_digest.get('GO_SM3_B64'):
            result.add_pass("SM3 Base64 摘要一致")
        else:
            result.add_fail("SM3 Base64 摘要一致", 
                f"Java: {java_digest.get('JAVA_SM3_B64', 'N/A')}, Go: {go_digest.get('GO_SM3_B64', 'N/A')}")
        
    except Exception as e:
        result.add_fail("SM3 Java↔Go 测试", str(e))
    
    return result.summary()

def generate_report(sm4_j2g, sm4_g2j, sm2_result, sm3_result):
    """生成测试报告"""
    total_passed = (
        sm4_j2g['passed'] + sm4_j2g['failed'] +
        sm4_g2j['passed'] + sm4_g2j['failed'] +
        sm2_result['passed'] + sm2_result['failed'] +
        sm3_result['passed'] + sm3_result['failed']
    )
    
    report = f"""# Java-Go SM2/SM3/SM4 互通性测试报告

**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 测试摘要

| 测试方向 | 通过 | 失败 | 总计 |
|---------|------|------|------|
| SM4 Java→Go | {sm4_j2g['passed']} | {sm4_j2g['failed']} | {sm4_j2g['passed'] + sm4_j2g['failed']} |
| SM4 Go→Java | {sm4_g2j['passed']} | {sm4_g2j['failed']} | {sm4_g2j['passed'] + sm4_g2j['failed']} |
| SM2 Java↔Go | {sm2_result['passed']} | {sm2_result['failed']} | {sm2_result['passed'] + sm2_result['failed']} |
| SM3 Java↔Go | {sm3_result['passed']} | {sm3_result['failed']} | {sm3_result['passed'] + sm3_result['failed']} |
| **总计** | {sm4_j2g['passed']+sm4_g2j['passed']+sm2_result['passed']+sm3_result['passed']} | {sm4_j2g['failed']+sm4_g2j['failed']+sm2_result['failed']+sm3_result['failed']} | {total_passed} |

## 详细结果

### SM4 Java→Go 测试结果
"""
    for detail in sm4_j2g['details']:
        status = "✅" if detail['status'] == "PASS" else "❌"
        report += f"\n{status} {detail['name']}"
        if 'detail' in detail:
            report += f": {detail['detail']}"
        if 'error' in detail:
            report += f": {detail['error']}"
    
    report += "\n\n### SM4 Go→Java 测试结果\n"
    for detail in sm4_g2j['details']:
        status = "✅" if detail['status'] == "PASS" else "❌"
        report += f"\n{status} {detail['name']}"
        if 'detail' in detail:
            report += f": {detail['detail']}"
        if 'error' in detail:
            report += f": {detail['error']}"
    
    report += "\n\n### SM2 Java↔Go 测试结果\n"
    for detail in sm2_result['details']:
        status = "✅" if detail['status'] == "PASS" else "❌"
        report += f"\n{status} {detail['name']}"
        if 'detail' in detail:
            report += f": {detail['detail']}"
        if 'error' in detail:
            report += f": {detail['error']}"
    
    report += "\n\n### SM3 Java↔Go 测试结果\n"
    for detail in sm3_result['details']:
        status = "✅" if detail['status'] == "PASS" else "❌"
        report += f"\n{status} {detail['name']}"
        if 'detail' in detail:
            report += f": {detail['detail']}"
        if 'error' in detail:
            report += f": {detail['error']}"
    
    total_failed = sm4_j2g['failed']+sm4_g2j['failed']+sm2_result['failed']+sm3_result['failed']
    if total_failed == 0:
        report += "\n\n## 结论\n\n✅ **所有测试通过！Java 和 Go 实现完全互通。**\n"
    else:
        report += f"\n\n## 结论\n\n⚠️ **有 {total_failed} 项测试失败，请检查互通性问题。**\n"
    
    return report

def main():
    print("=" * 60)
    print("Java-Go SM2/SM3/SM4 互通性测试")
    print("=" * 60)
    
    # 1. Java 自测
    run_java_generate_test_data()
    
    # 2. Go 单元测试
    if not run_go_tests():
        print("Go 单元测试失败，继续互通性测试...")
    
    # 3. SM4 Java→Go
    sm4_j2g = test_sm4_java_to_go()
    
    # 4. SM4 Go→Java
    sm4_g2j = test_sm4_go_to_java()
    
    # 5. SM2 Java↔Go
    sm2_result = test_sm2_java_go()
    
    # 6. SM3 Java↔Go
    sm3_result = test_sm3_java_go()
    
    # 生成报告
    report = generate_report(sm4_j2g, sm4_g2j, sm2_result, sm3_result)
    
    report_file = TESTCASE_DIR / "java_go_interop_test_report.md"
    report_file.write_text(report, encoding='utf-8')
    
    print("\n" + "=" * 60)
    print(f"测试报告已生成：{report_file}")
    print("=" * 60)
    print(report)

if __name__ == "__main__":
    main()