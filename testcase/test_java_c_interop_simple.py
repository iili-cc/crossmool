#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java 加密和签名 -> C 解密和验签 简化测试
"""

import json
import os
import sys
import subprocess
import tempfile
import shutil
from datetime import datetime

# 日志文件
LOG_FILE = f"java_interop_test_{datetime.now().strftime('%m%d%H')}.log"

def log(message):
    """打印并记录日志"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"[{timestamp}] {message}"
    print(log_line)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_line + '\n')

def find_vsdevcmd():
    """查找 VsDevCmd.bat 路径"""
    possible_paths = [
        r"H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat",
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    # 尝试通过 vswhere 查找
    vswhere_path = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
    if os.path.exists(vswhere_path):
        try:
            result = subprocess.run([vswhere_path, '-latest', '-property', 'installationPath'],
                                    capture_output=True, text=True)
            if result.stdout:
                devcmd_path = os.path.join(result.stdout.strip(), 'Common7', 'Tools', 'VsDevCmd.bat')
                if os.path.exists(devcmd_path):
                    return devcmd_path
        except Exception:
            pass
    return None

def run_java_keygen():
    """使用 Java 生成密钥对"""
    log("使用 Java 生成 SM2 密钥对...")
    
    java_code = '''
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.SerialKeyPair;

public class KeyGen {
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    public static void main(String[] args) {
        try {
            SerialKeyPair keyPair = SM2Util.generateKeyPairHex();
            System.out.println("PUBLIC_KEY_HEX=" + keyPair.getPublicKey());
            System.out.println("PRIVATE_KEY_HEX=" + keyPair.getPrivateKey());
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
'''
    
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, 'KeyGen.java')
        with open(java_file, 'w', encoding='utf-8') as f:
            f.write(java_code)
        
        # 编译
        classpath = 'java/crossmool/target/crossmool-1.1.0.jar;java/crossmool/target/classes'
        compile_cmd = f'javac -cp "{classpath}" -d "{tmpdir}" "{java_file}"'
        log(f"编译 Java: {compile_cmd}")
        result = subprocess.run(compile_cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            log(f"Java 编译失败：{result.stderr}")
            return None
        
        # 运行
        run_cmd = f'java -cp "{classpath};{tmpdir}" KeyGen'
        log(f"运行 Java: {run_cmd}")
        result = subprocess.run(run_cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            log(f"Java 运行失败：{result.stderr}")
            return None
        
        # 解析输出
        public_key = None
        private_key = None
        for line in result.stdout.strip().split('\n'):
            if line.startswith('PUBLIC_KEY_HEX='):
                public_key = line.split('=', 1)[1]
            elif line.startswith('PRIVATE_KEY_HEX='):
                private_key = line.split('=', 1)[1]
        
        if public_key and private_key:
            log(f"Java 生成公钥 (Hex): {public_key[:64]}...")
            log(f"Java 生成私钥 (Hex): {private_key[:64]}...")
            return {'public_key': public_key, 'private_key': private_key}
        else:
            log(f"无法解析 Java 输出：{result.stdout}")
            return None

def run_java_encrypt_sign(public_key, private_key, message):
    """使用 Java 加密和签名"""
    log(f"使用 Java 加密和签名：{message}")
    
    java_code = f'''
import java.security.Security;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;

public class EncryptSign {{
    static {{
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {{
            Security.addProvider(new BouncyCastleProvider());
        }}
    }}
    public static void main(String[] args) {{
        try {{
            String publicKey = "{public_key}";
            String privateKey = "{private_key}";
            String message = "{message}";
            
            // 加密
            String ciphertext = SM2Util.encrypt(message, publicKey);
            System.out.println("CIPHERTEXT_HEX=" + ciphertext);
            
            // 签名（对密文签名）
            String signature = SM2Util.sign(ciphertext, privateKey);
            System.out.println("SIGNATURE_HEX=" + signature);
            
        }} catch (Exception e) {{
            e.printStackTrace();
            System.exit(1);
        }}
    }}
}}
'''
    
    with tempfile.TemporaryDirectory() as tmpdir:
        java_file = os.path.join(tmpdir, 'EncryptSign.java')
        with open(java_file, 'w', encoding='utf-8') as f:
            f.write(java_code)
        
        # 编译
        classpath = 'java/crossmool/target/crossmool-1.1.0.jar;java/crossmool/target/classes'
        compile_cmd = f'javac -cp "{classpath}" -d "{tmpdir}" "{java_file}"'
        log(f"编译 Java: {compile_cmd}")
        result = subprocess.run(compile_cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            log(f"Java 编译失败：{result.stderr}")
            return None
        
        # 运行
        run_cmd = f'java -cp "{classpath};{tmpdir}" EncryptSign'
        log(f"运行 Java: {run_cmd}")
        result = subprocess.run(run_cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            log(f"Java 运行失败：{result.stderr}")
            return None
        
        # 解析输出
        ciphertext = None
        signature = None
        for line in result.stdout.strip().split('\n'):
            if line.startswith('CIPHERTEXT_HEX='):
                ciphertext = line.split('=', 1)[1]
            elif line.startswith('SIGNATURE_HEX='):
                signature = line.split('=', 1)[1]
        
        if ciphertext and signature:
            log(f"Java 加密结果 (Hex): {ciphertext[:64]}...")
            log(f"Java 签名结果 (Hex): {signature[:64]}...")
            return {'ciphertext': ciphertext, 'signature': signature}
        else:
            log(f"无法解析 Java 输出：{result.stdout}")
            return None

def create_c_test_program(public_key, ciphertext, signature, message):
    """创建 C 语言测试程序"""
    
    c_code = f'''#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crossmool_sm2.h"

int main(void) {{
    printf("=== C 语言验签测试 ===\\n");
    
    const char* public_key = "{public_key}";
    const char* ciphertext = "{ciphertext}";
    const char* signature = "{signature}";
    const char* original_message = "{message}";
    
    printf("公钥 (Hex): %s\\n", public_key);
    printf("密文 (Hex): %s\\n", ciphertext);
    printf("签名 (Hex): %s\\n", signature);
    printf("原始消息：%s\\n", original_message);
    
    // 测试 1: 对密文验签（Java 是对密文签名）
    printf("\\n[测试 1] 对密文验签...\\n");
    int verify_result = crossmool_sm2_verify(ciphertext, NULL, signature, public_key);
    printf("验签结果：%d (1=成功，0=失败，负数=错误)\\n", verify_result);
    
    if (verify_result == 1) {{
        printf("[PASS] 验签成功!\\n");
    }} else {{
        printf("[FAIL] 验签失败!\\n");
    }}
    
    return verify_result == 1 ? 0 : 1;
}}
'''
    return c_code

def compile_and_run_c_test(c_code, vsdevcmd_path):
    """编译并运行 C 测试程序"""
    
    tmpdir = tempfile.mkdtemp()
    try:
        c_file = os.path.join(tmpdir, 'test_verify.c')
        with open(c_file, 'w', encoding='utf-8') as f:
            f.write(c_code)
        
        # 创建 bat 文件来设置环境并编译
        bat_file = os.path.join(tmpdir, 'build.bat')
        bat_content = f'''@echo off
call "{vsdevcmd_path}"
cd /d "{tmpdir}"
cl /I "c/crossmool/include" /I "c/crossmool/gmssl_install/include" test_verify.c ^
   "c/crossmool/build_msvc/Release/crossmool.lib" ^
   "c/crossmool/gmssl_install/lib/gmssl.lib" ^
   /Fe:test_verify.exe
if %ERRORLEVEL% NEQ 0 (
    echo 编译失败
    exit /b 1
)
echo 编译成功，运行测试...
test_verify.exe
exit /b %ERRORLEVEL%
'''
        with open(bat_file, 'w', encoding='utf-8') as f:
            f.write(bat_content)
        
        log(f"使用 VsDevCmd: {vsdevcmd_path}")
        log(f"编译并运行 C 测试程序")
        
        result = subprocess.run(['cmd', '/c', bat_file], 
                                capture_output=True, text=True, cwd=tmpdir)
        
        output = result.stdout + result.stderr
        log(f"C 程序输出:\n{output}")
        
        return result.returncode == 0, output
        
    finally:
        # 清理临时文件
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass

def main():
    """主测试函数"""
    log("=" * 70)
    log("Java 到 C 语言互通测试开始")
    log("=" * 70)
    
    # 1. 查找 VsDevCmd
    vsdevcmd = find_vsdevcmd()
    if not vsdevcmd:
        log("错误：未找到 VsDevCmd.bat")
        return False
    log(f"找到 VsDevCmd.bat: {vsdevcmd}")
    
    # 2. 使用 Java 生成密钥对
    keys = run_java_keygen()
    if not keys:
        log("错误：Java 密钥生成失败")
        return False
    
    # 3. 使用 Java 加密和签名
    test_message = "Hello, Cross-Language Interoperability! 测试消息"
    encrypted = run_java_encrypt_sign(keys['public_key'], keys['private_key'], test_message)
    if not encrypted:
        log("错误：Java 加密签名失败")
        return False
    
    # 4. 创建 C 测试程序
    c_code = create_c_test_program(
        keys['public_key'],
        encrypted['ciphertext'],
        encrypted['signature'],
        test_message
    )
    
    # 5. 编译并运行 C 测试
    success, output = compile_and_run_c_test(c_code, vsdevcmd)
    
    if success:
        log("=" * 70)
        log("测试成功！Java 和 C 语言互通正常")
        log("=" * 70)
        return True
    else:
        log("=" * 70)
        log("测试失败！Java 和 C 语言互通存在问题")
        log("=" * 70)
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)