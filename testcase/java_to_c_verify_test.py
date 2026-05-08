#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java 到 C 语言互通测试脚本

功能:
1. 读取 testcase/keys/java/keys.json 中的密钥文件
2. 读取 testcase/results/java_encrypt/ 目录下的 Java 加密结果
3. 使用 MSVC 编译器调用 c/crossmool/build_msvc/Release/crossmool.dll
4. 执行 crossmool_sm2_verify 和 crossmool_sm2_decrypt 函数进行验签和解密
5. 记录详细日志到 java_interop_test_20260507.log
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

# 配置路径
C_INCLUDE_PATH = r"c/crossmool/include"
C_DLL_PATH = r"c/crossmool/build_msvc/Release"
C_DLL_NAME = "crossmool.dll"
JAVA_KEYS_FILE = "testcase/keys/java/keys.json"
JAVA_ENCRYPT_DIR = "testcase/results/java_encrypt"
# 使用绝对路径确保日志文件正确写入
LOG_FILE = "java_interop_test_20260507.log"

class Logger:
    """日志记录器"""
    def __init__(self, log_file):
        self.log_file = log_file
        self.log_lines = []
        
    def log(self, message):
        """记录日志到内存和文件"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.log_lines.append(log_entry)
        print(log_entry)
        
    def save(self):
        """保存日志到文件"""
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.log_lines))

logger = Logger(LOG_FILE)

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def get_msvc_env():
    """获取 x64 MSVC 编译器的环境变量"""
    # 尝试多个 VsDevCmd.bat 路径
    vsdevcmd_paths = [
        r"H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat",
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat",
    ]
    
    vsdevcmd_path = None
    for p in vsdevcmd_paths:
        if os.path.exists(p):
            vsdevcmd_path = p
            logger.log(f"找到 VsDevCmd.bat: {p}")
            break
    
    if not vsdevcmd_path:
        logger.log("错误：找不到 VsDevCmd.bat")
        return None
    
    # 尝试使用 vcvars64.bat 直接获取 x64 环境
    # vcvars64.bat 是专门用于设置 x64 编译环境的批处理文件
    vcvars64_path = vsdevcmd_path.replace("VsDevCmd.bat", "VC\\Auxiliary\\Build\\vcvars64.bat")
    
    if not os.path.exists(vcvars64_path):
        # 尝试旧版本路径
        vcvars64_path = vsdevcmd_path.replace("VsDevCmd.bat", "vcvars64.bat")
    
    use_vcvars64 = os.path.exists(vcvars64_path)
    
    if use_vcvars64:
        logger.log(f"使用 vcvars64.bat: {vcvars64_path}")
        cmd = f'cmd /c "call "{vcvars64_path}" && set"'
    else:
        logger.log(f"使用 VsDevCmd.bat: {vsdevcmd_path}")
        cmd = f'cmd /c "call "{vsdevcmd_path}" -host_arch=amd64 -arch=amd64 && set"'
    
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        encoding='gbk',
        errors='ignore',
        timeout=60
    )
    
    if result.returncode != 0:
        logger.log(f"VS 环境初始化失败：{result.stderr[:200] if result.stderr else '未知错误'}")
        return None
    
    # 解析环境变量
    env_vars = os.environ.copy()
    for line in result.stdout.split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            env_vars[key.strip()] = value.strip()
    
    # 验证架构
    platform = env_vars.get('PLATFORM', '')
    processor_arch = env_vars.get('PROCESSOR_ARCHITECTURE', '')
    
    logger.log(f"PLATFORM={platform}, PROCESSOR_ARCHITECTURE={processor_arch}")
    
    return env_vars

def run_c_verify(ciphertext_hex, signature_hex, content_to_verify, sign_public_key_hex):
    """
    使用 MSVC 编译器编译并运行 C 程序执行验签
    """
    def escape_for_c_string(s):
        """转义字符串为 C 语言兼容格式，使用 Unicode 转义处理非 ASCII 字符"""
        result = []
        for c in s:
            if c == '\\':
                result.append('\\\\')
            elif c == '"':
                result.append('\\"')
            elif c == '\n':
                result.append('\\n')
            elif c == '\r':
                result.append('\\r')
            elif c == '\t':
                result.append('\\t')
            elif ord(c) < 32:
                result.append(f'\\x{ord(c):02x}')
            elif ord(c) >= 128:
                # 非 ASCII 字符使用 Unicode 转义
                result.append(f'\\u{ord(c):04x}')
            else:
                result.append(c)
        return ''.join(result)
    
    escaped_content = escape_for_c_string(content_to_verify)
    
    c_code = f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

int main() {{
    const char* signature = "{signature_hex}";
    const char* public_key = "{sign_public_key_hex}";
    const char* content = "{escaped_content}";
    
    int verify_ret = crossmool_sm2_verify(content, NULL, signature, public_key);
    
    if (verify_ret == 1) {{
        printf("VERIFY_SUCCESS");
        return 0;
    }} else if (verify_ret == 0) {{
        printf("VERIFY_FAILED");
        return 1;
    }} else {{
        fprintf(stderr, "VERIFY_ERROR:%d", verify_ret);
        return 2;
    }}
}}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_c_file = os.path.join(temp_dir, "verify_temp.c")
        temp_exe_file = os.path.join(temp_dir, "verify_temp.exe")
        
        with open(temp_c_file, 'w', encoding='utf-8') as f:
            f.write(c_code)
        
        try:
            # 获取 MSVC x64 环境
            msvc_env = get_msvc_env()
            if not msvc_env:
                return False, "无法获取 MSVC x64 环境"
            
            # 编译
            compile_cmd = f'cl.exe /I"{C_INCLUDE_PATH}" "{temp_c_file}" /Fe"{temp_exe_file}" /link /LIBPATH:"{C_DLL_PATH}" crossmool.lib'
            
            compile_result = subprocess.run(
                compile_cmd,
                shell=True,
                capture_output=True,
                encoding='gbk',
                errors='ignore',
                env=msvc_env
            )
            
            if compile_result.returncode != 0:
                stderr = compile_result.stderr if compile_result.stderr else "未知错误"
                stdout = compile_result.stdout if compile_result.stdout else ""
                return False, f"MSVC 编译失败：{stderr}\n{stdout}"
            
            logger.log("MSVC 编译成功")
            
            # 复制 exe 到 DLL 目录以便运行
            temp_exe_in_dll_dir = os.path.join(C_DLL_PATH, "temp_verify.exe")
            shutil.copy(temp_exe_file, temp_exe_in_dll_dir)
            
            try:
                run_result = subprocess.run(
                    f'cmd /c "cd /d {C_DLL_PATH} && temp_verify.exe"',
                    shell=True,
                    capture_output=True,
                    encoding='gbk',
                    errors='ignore'
                )
                
                output = run_result.stdout.strip()
                stderr = run_result.stderr.strip() if run_result.stderr else ""
                
                if run_result.returncode == 0 and output == "VERIFY_SUCCESS":
                    return True, "验签成功"
                elif "VERIFY_FAILED" in output or "VERIFY_FAILED" in stderr:
                    return False, "验签失败：签名不匹配"
                else:
                    error_msg = stderr if stderr else f"输出：{output}, 返回码：{run_result.returncode}"
                    return False, f"验签错误：{error_msg}"
                    
            finally:
                if os.path.exists(temp_exe_in_dll_dir):
                    os.remove(temp_exe_in_dll_dir)
                    
        except Exception as e:
            return False, f"编译或运行过程出错：{e}"

def run_c_decrypt(ciphertext_hex, dec_private_key_hex):
    """
    使用 MSVC 编译器编译并运行 C 程序执行解密
    """
    c_code = f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

int main() {{
    const char* ciphertext = "{ciphertext_hex}";
    const char* private_key = "{dec_private_key_hex}";
    
    char* plaintext = NULL;
    int ret = crossmool_sm2_decrypt(ciphertext, private_key, NULL, &plaintext);
    
    if (ret != 0 || plaintext == NULL) {{
        fprintf(stderr, "DECRYPT_ERROR:%d", ret);
        return 1;
    }}
    
    printf("%s", plaintext);
    
    free(plaintext);
    return 0;
}}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_c_file = os.path.join(temp_dir, "decrypt_temp.c")
        temp_exe_file = os.path.join(temp_dir, "decrypt_temp.exe")
        
        with open(temp_c_file, 'w', encoding='utf-8') as f:
            f.write(c_code)
        
        try:
            # 获取 MSVC x64 环境
            msvc_env = get_msvc_env()
            if not msvc_env:
                return False, "无法获取 MSVC x64 环境"
            
            # 编译
            compile_cmd = f'cl.exe /I"{C_INCLUDE_PATH}" "{temp_c_file}" /Fe"{temp_exe_file}" /link /LIBPATH:"{C_DLL_PATH}" crossmool.lib'
            
            compile_result = subprocess.run(
                compile_cmd,
                shell=True,
                capture_output=True,
                encoding='gbk',
                errors='ignore',
                env=msvc_env
            )
            
            if compile_result.returncode != 0:
                stderr = compile_result.stderr if compile_result.stderr else "未知错误"
                return False, f"MSVC 编译失败：{stderr}"
            
            logger.log("MSVC 编译成功")
            
            # 复制 exe 到 DLL 目录以便运行
            temp_exe_in_dll_dir = os.path.join(C_DLL_PATH, "temp_decrypt.exe")
            shutil.copy(temp_exe_file, temp_exe_in_dll_dir)
            
            try:
                run_result = subprocess.run(
                    f'cmd /c "cd /d {C_DLL_PATH} && temp_decrypt.exe"',
                    shell=True,
                    capture_output=True,
                    encoding='gbk',
                    errors='ignore'
                )
                
                if run_result.returncode != 0:
                    stderr = run_result.stderr if run_result.stderr else "未知错误"
                    return False, f"解密错误：{stderr}"
                
                decrypted_text = run_result.stdout.strip()
                return True, decrypted_text
                
            finally:
                if os.path.exists(temp_exe_in_dll_dir):
                    os.remove(temp_exe_in_dll_dir)
                    
        except Exception as e:
            return False, f"编译或运行过程出错：{e}"

def test_java_to_c_interop():
    """测试 Java 到 C 语言的互通性"""
    logger.log("=" * 70)
    logger.log("Java 到 C 语言互通测试开始")
    logger.log("=" * 70)
    
    # 检查 DLL 文件
    dll_path = os.path.join(C_DLL_PATH, C_DLL_NAME)
    if not os.path.exists(dll_path):
        logger.log(f"错误：找不到 C DLL 文件：{dll_path}")
        return False
    
    logger.log(f"C DLL 路径：{dll_path}")
    
    # 检查.lib 文件
    lib_path = os.path.join(C_DLL_PATH, "crossmool.lib")
    if not os.path.exists(lib_path):
        logger.log(f"警告：找不到.lib 文件：{lib_path}")
    
    # 加载 Java 密钥
    if not os.path.exists(JAVA_KEYS_FILE):
        logger.log(f"错误：找不到 Java 密钥文件：{JAVA_KEYS_FILE}")
        return False
    
    logger.log(f"加载 Java 密钥文件：{JAVA_KEYS_FILE}")
    java_keys = load_json_file(JAVA_KEYS_FILE)
    
    sign_public_key_hex = java_keys["signature_public_key"]["hex"]
    dec_private_key_hex = java_keys["encryption_private_key"]["hex"]
    
    logger.log(f"  验签公钥 (Hex): {sign_public_key_hex[:40]}...")
    logger.log(f"  解密私钥 (Hex): {dec_private_key_hex[:40]}...")
    
    # 检查 Java 加密结果目录
    if not os.path.exists(JAVA_ENCRYPT_DIR):
        logger.log(f"错误：找不到 Java 加密结果目录：{JAVA_ENCRYPT_DIR}")
        return False
    
    json_files = sorted(Path(JAVA_ENCRYPT_DIR).glob("test_*.json"))
    
    if not json_files:
        logger.log(f"警告：在 {JAVA_ENCRYPT_DIR} 中未找到测试用例文件")
        return False
    
    logger.log(f"\n找到 {len(json_files)} 个 Java 加密结果文件")
    
    # 测试结果统计
    total = 0
    verify_success = 0
    decrypt_success = 0
    full_success = 0
    
    for json_file in json_files:
        if json_file.name.startswith("summary"):
            continue
        
        total += 1
        logger.log(f"\n{'=' * 70}")
        logger.log(f"测试用例 {total}: {json_file.name}")
        logger.log("=" * 70)
        
        try:
            result_data = load_json_file(str(json_file))
            test_id = result_data.get("test_case_id", "unknown")
            test_name = result_data.get("test_case_name", "unknown")
            plaintext = result_data.get("plaintext", "")
            ciphertext_hex = result_data.get("ciphertext_hex", "")
            signature_hex = result_data.get("signature_hex", "")
            
            logger.log(f"  测试 ID: {test_id}")
            logger.log(f"  测试名称：{test_name}")
            logger.log(f"  原始明文：{plaintext[:50]}{'...' if len(plaintext) > 50 else ''}")
            logger.log(f"  密文 (Hex): {ciphertext_hex[:60]}...")
            logger.log(f"  签名 (Hex): {signature_hex[:60]}...")
            
            # 步骤 1: C 语言验签（Java 对密文签名，所以用密文验签）
            logger.log(f"\n  [步骤 1] 执行 C 语言验签（对密文验签）...")
            verify_ok, verify_msg = run_c_verify(
                ciphertext_hex, signature_hex, ciphertext_hex, sign_public_key_hex
            )
            
            if verify_ok:
                logger.log(f"  [OK] {verify_msg}")
                verify_success += 1
            else:
                logger.log(f"  [FAIL] {verify_msg}")
                continue
            
            # 步骤 2: C 语言解密
            logger.log(f"\n  [步骤 2] 执行 C 语言解密...")
            decrypt_ok, decrypt_result = run_c_decrypt(ciphertext_hex, dec_private_key_hex)
            
            if decrypt_ok:
                logger.log(f"  [OK] 解密成功")
                logger.log(f"  解密结果：{decrypt_result[:50]}{'...' if len(decrypt_result) > 50 else ''}")
                decrypt_success += 1
                
                # 步骤 3: 验证解密结果
                logger.log(f"\n  [步骤 3] 验证解密结果...")
                if decrypt_result == plaintext:
                    logger.log(f"  [OK] 解密结果与原始明文匹配")
                    full_success += 1
                else:
                    logger.log(f"  [FAIL] 解密结果不匹配")
                    logger.log(f"  期望：{plaintext[:50]}{'...' if len(plaintext) > 50 else ''}")
                    logger.log(f"  实际：{decrypt_result[:50]}{'...' if len(decrypt_result) > 50 else ''}")
            else:
                logger.log(f"  [FAIL] {decrypt_result}")
        
        except Exception as e:
            logger.log(f"  [ERROR] 处理文件时出错：{e}")
    
    # 打印总结
    logger.log(f"\n{'=' * 70}")
    logger.log("测试总结")
    logger.log("=" * 70)
    logger.log(f"总测试用例：{total}")
    logger.log(f"验签成功：{verify_success}")
    logger.log(f"解密成功：{decrypt_success}")
    logger.log(f"完全成功 (验签 + 解密 + 匹配): {full_success}")
    
    if total > 0:
        logger.log(f"成功率：{full_success / total * 100:.1f}%")
    
    logger.log("=" * 70)
    
    return full_success == total

def main():
    """主函数"""
    try:
        success = test_java_to_c_interop()
        
        # 保存日志
        logger.save()
        logger.log(f"\n日志已保存到：{LOG_FILE}")
        
        return 0 if success else 1
    
    except Exception as e:
        logger.log(f"\n测试过程中发生错误：{e}")
        logger.save()
        return 1

if __name__ == "__main__":
    sys.exit(main())