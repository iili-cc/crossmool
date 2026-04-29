#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C 语言 SM2 解密验签互操作性测试脚本

功能:
1. 读取 testcase/keys/c/keys.json 中的解密私钥和验签公钥
2. 读取其他语言加密生成的密文和签名 JSON 文件
3. 使用 MSVC 编译器调用 c/crossmool/build_msvc/Release/crossmool.dll 动态库
4. 执行 crossmool_sm2_verify_decrypt 函数验证并解密
5. 输出验证和解密结果到 testcase/results/c_verify 目录
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# 配置路径
C_INCLUDE_PATH = r"c/crossmool/include"
C_DLL_PATH = r"c/crossmool/build_msvc/Release"
C_DLL_NAME = "crossmool.dll"
KEYS_FILE = "testcase/keys/c/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/c_verify"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_c_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    """
    使用 MSVC 编译器编译并运行 C 程序执行验签和解密
    
    参数:
        ciphertext_hex: 密文 (Hex 格式)
        signature_hex: 签名 (Hex 格式)
        sign_public_key_hex: 验签公钥 (Hex 格式)
        dec_private_key_hex: 解密私钥 (Hex 格式)
    
    返回:
        tuple: (success: bool, decrypted_text: str or error_message: str)
    """
    # 创建临时 C 测试程序
    c_code = f'''#include <stdio.h>
#include <string.h>
#include "crossmool.h"

int main() {{
    const char* ciphertext = "{ciphertext_hex}";
    const char* signature = "{signature_hex}";
    const char* sign_public_key = "{sign_public_key_hex}";
    const char* dec_private_key = "{dec_private_key_hex}";
    
    char* plaintext = NULL;
    int ret = crossmool_sm2_verify_decrypt(ciphertext, signature, sign_public_key, dec_private_key, NULL, &plaintext);
    
    if (ret != CROSSMOOL_SUCCESS || plaintext == NULL) {{
        fprintf(stderr, "ERROR:verify_decrypt failed: %d\\n", ret);
        return 1;
    }}
    
    // 输出解密后的明文
    printf("%s", plaintext);
    
    free(plaintext);
    return 0;
}}
'''
    # 创建临时目录存放编译文件
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_c_file = os.path.join(temp_dir, "c_verify_temp.c")
        temp_exe_file = os.path.join(temp_dir, "c_verify_temp.exe")
        
        # 写入临时 C 文件
        with open(temp_c_file, 'w', encoding='utf-8') as f:
            f.write(c_code)
        
        try:
            # 使用 MSVC 编译器 (cl.exe) 通过 Developer Command Prompt for VS
            vsdevcmd_path = r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
            
            # 检查 VsDevCmd.bat 是否存在
            if not os.path.exists(vsdevcmd_path):
                # 尝试其他可能路径
                alt_paths = [
                    r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat",
                    r"C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat",
                ]
                for alt_path in alt_paths:
                    if os.path.exists(alt_path):
                        vsdevcmd_path = alt_path
                        break
            
            if os.path.exists(vsdevcmd_path):
                # 使用 MSVC 编译
                cl_cmd = f'cmd /c "call "{vsdevcmd_path}" && cl.exe /I"{C_INCLUDE_PATH}" "{temp_c_file}" /Fe"{temp_exe_file}" /link /LIBPATH:"{C_DLL_PATH}" crossmool.lib"'
                
                compile_result = subprocess.run(
                    cl_cmd,
                    shell=True,
                    capture_output=True,
                    encoding='gbk',
                    errors='ignore'
                )
                
                if compile_result.returncode != 0:
                    stderr = compile_result.stderr if compile_result.stderr else "未知错误"
                    return False, f"MSVC 编译失败：{stderr}"
            else:
                # 使用 GCC (MinGW) 作为备选方案
                gcc_path = shutil.which("gcc")
                if not gcc_path:
                    return False, "找不到 gcc 编译器"
                
                # GCC 编译命令
                gcc_cmd = f'"{gcc_path}" -I"{C_INCLUDE_PATH}" "{temp_c_file}" -o "{temp_exe_file}" -L"{C_DLL_PATH}" -lcrossmool'
                
                compile_result = subprocess.run(
                    gcc_cmd,
                    shell=True,
                    capture_output=True,
                    encoding='utf-8',
                    errors='ignore'
                )
                
                if compile_result.returncode != 0:
                    stderr = compile_result.stderr if compile_result.stderr else "未知错误"
                    return False, f"GCC 编译失败：{stderr}"
            
            # 运行 C 程序
            # 将临时 exe 复制到 DLL 所在目录，避免 PATH 问题
            temp_exe_in_dll_dir = os.path.join(C_DLL_PATH, "temp_verify.exe")
            shutil.copy(temp_exe_file, temp_exe_in_dll_dir)
            
            try:
                # 使用绝对路径运行
                run_result = subprocess.run(
                    f'cmd /c "cd /d {C_DLL_PATH} && temp_verify.exe"',
                    shell=True,
                    capture_output=True,
                    encoding='utf-8',
                    errors='ignore'
                )
                
                if run_result.returncode != 0:
                    stderr = run_result.stderr if run_result.stderr else "未知错误"
                    if "ERROR:" in stderr:
                        error_msg = stderr.split("ERROR:")[1].strip().split("\n")[0]
                    else:
                        error_msg = stderr
                    return False, error_msg
                
                # 输出解密后的明文
                decrypted_text = run_result.stdout.strip()
                return True, decrypted_text
                
            finally:
                # 清理临时文件
                if os.path.exists(temp_exe_in_dll_dir):
                    os.remove(temp_exe_in_dll_dir)
                    
        except Exception as e:
            return False, f"编译或运行过程出错：{e}"

def verify_language_results(language, output_dir, expected_plaintexts):
    """
    验证指定语言的加密结果
    
    参数:
        language: 语言名称 (java, cpp, csharp, golang, javascript, python, rust)
        output_dir: 该语言的加密结果目录
        expected_plaintexts: 期望的明文字典 {test_id: plaintext}
    
    返回:
        dict: 验证结果统计
    """
    results = []
    success_count = 0
    fail_count = 0
    
    # 加载 C 密钥
    keys = load_json_file(KEYS_FILE)
    sign_public_key_hex = keys["encryption_public_key"]["hex"]
    dec_private_key_hex = keys["signature_private_key"]["hex"]
    
    # 遍历加密结果目录
    if not os.path.exists(output_dir):
        print(f"\n警告：加密结果目录不存在：{output_dir}")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    json_files = sorted(Path(output_dir).glob("test_*.json"))
    
    if not json_files:
        print(f"\n警告：在 {output_dir} 中未找到测试用例文件")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    print(f"\n找到 {len(json_files)} 个加密结果文件")
    
    for json_file in json_files:
        # 跳过汇总文件
        if json_file.name.startswith("summary"):
            continue
        
        try:
            result_data = load_json_file(str(json_file))
            test_id = result_data.get("test_case_id", "unknown")
            test_name = result_data.get("test_case_name", "unknown")
            expected_plaintext = result_data.get("plaintext", "")
            ciphertext_hex = result_data.get("ciphertext_hex", "")
            signature_hex = result_data.get("signature_hex", "")
            
            print(f"\n  测试用例 {test_id}: {test_name}")
            print(f"    来源语言：{language}")
            print(f"    密文 (Hex): {ciphertext_hex[:60]}...")
            
            # 执行验签和解密
            success, decrypted_or_error = run_c_verify_decrypt(
                ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex
            )
            
            if success:
                # 验证解密结果是否与原始明文一致
                if decrypted_or_error == expected_plaintext:
                    print(f"    ✓ 验签成功，解密结果匹配")
                    print(f"    解密文本：{decrypted_or_error[:50]}{'...' if len(decrypted_or_error) > 50 else ''}")
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
                    print(f"    ✗ 验签成功，但解密结果不匹配")
                    print(f"    期望：{expected_plaintext[:50]}{'...' if len(expected_plaintext) > 50 else ''}")
                    print(f"    实际：{decrypted_or_error[:50]}{'...' if len(decrypted_or_error) > 50 else ''}")
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
                print(f"    ✗ 验签失败：{decrypted_or_error}")
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
            print(f"\n  处理文件 {json_file.name} 时出错：{e}")
            fail_count += 1
    
    return {
        "total": len(json_files),
        "success": success_count,
        "failed": fail_count,
        "results": results
    }

def main():
    """主函数"""
    print("=" * 70)
    print("C 语言 SM2 解密验签互操作性测试")
    print("=" * 70)
    
    # 检查 DLL 文件
    dll_path = os.path.join(C_DLL_PATH, C_DLL_NAME)
    if not os.path.exists(dll_path):
        print(f"错误：找不到 C DLL 文件：{dll_path}")
        print("请确保已使用 MSVC 编译 C 项目")
        sys.exit(1)
    print(f"\nC DLL 路径：{dll_path}")
    
    # 检查.lib 文件
    lib_path = os.path.join(C_DLL_PATH, "crossmool.lib")
    if not os.path.exists(lib_path):
        print(f"警告：找不到.lib 文件：{lib_path}")
        print("可能需要先编译 C 项目生成.lib 文件")
    
    # 检查密钥文件
    if not os.path.exists(KEYS_FILE):
        print(f"错误：找不到密钥文件：{KEYS_FILE}")
        sys.exit(1)
    
    # 加载密钥
    print(f"\n加载密钥文件：{KEYS_FILE}")
    keys = load_json_file(KEYS_FILE)
    sign_public_key_hex = keys["encryption_public_key"]["hex"]
    dec_private_key_hex = keys["signature_private_key"]["hex"]
    print(f"  验签公钥 (Hex): {sign_public_key_hex[:40]}...")
    print(f"  解密私钥 (Hex): {dec_private_key_hex[:40]}...")
    
    # 加载测试数据以获取期望明文
    if not os.path.exists(TEST_DATA_FILE):
        print(f"错误：找不到测试数据文件：{TEST_DATA_FILE}")
        sys.exit(1)
    
    test_data = load_json_file(TEST_DATA_FILE)
    expected_plaintexts = {tc["id"]: tc["plaintext"] for tc in test_data["test_cases"]}
    
    # 定义要测试的语言及其加密结果目录
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
    
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n验证结果输出目录：{OUTPUT_DIR}")
    
    # 处理每种语言
    all_results = {}
    total_tests = 0
    total_success = 0
    total_failed = 0
    
    for language, encrypt_dir in languages:
        print(f"\n{'=' * 70}")
        print(f"验证 {language.upper()} 语言的加密结果")
        print(f"{'=' * 70}")
        
        lang_result = verify_language_results(language, encrypt_dir, expected_plaintexts)
        all_results[language] = lang_result
        
        total_tests += lang_result["total"]
        total_success += lang_result["success"]
        total_failed += lang_result["failed"]
        
        # 保存该语言的验证结果
        if lang_result["total"] > 0:
            lang_output_file = os.path.join(OUTPUT_DIR, f"{language}_verify_summary.json")
            save_json_file(lang_output_file, lang_result)
            print(f"\n  {language} 语言验证结果已保存到：{lang_output_file}")
            print(f"  总计：{lang_result['total']}, 成功：{lang_result['success']}, 失败：{lang_result['failed']}")
    
    # 保存汇总结果
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
    print(f"\n汇总结果已保存到：{summary_file}")
    
    # 打印总结
    print("\n" + "=" * 70)
    print("测试总结")
    print("=" * 70)
    print(f"总测试用例：{total_tests}")
    print(f"成功：{total_success}")
    print(f"失败：{total_failed}")
    if total_tests > 0:
        print(f"成功率：{total_success / total_tests * 100:.1f}%")
    print("=" * 70)
    
    return 0 if total_failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())