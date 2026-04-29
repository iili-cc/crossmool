#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C 语言 SM2 加密和签名互操作性测试脚本

功能:
1. 读取 testcase/keys/c/keys.json 中的密钥
2. 读取 testcase/test_data.json 中的测试数据
3. 使用 MSVC 编译器调用 c/crossmool/build_msvc/Release/crossmool.dll 动态库
4. 执行 crossmool_sm2_encrypt_sign 函数加密签名并输出 Hex 格式结果
5. 输出结果到 testcase/results/c_encrypt 目录
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
OUTPUT_DIR = "testcase/results/c_encrypt"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_c_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    """
    使用 MSVC 编译器编译并运行 C 程序执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 转义 C 字符串中的特殊字符
    content_escaped = content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    
    # 创建临时 C 测试程序
    c_code = f'''#include <stdio.h>
#include <string.h>
#include "crossmool.h"

int main() {{
    const char* content = "{content_escaped}";
    const char* enc_public_key = "{enc_public_key_hex}";
    const char* sign_private_key = "{sign_private_key_hex}";
    
    crossmool_sm2_cipher_sig_pair_t* result = NULL;
    int ret = crossmool_sm2_encrypt_sign(content, NULL, enc_public_key, sign_private_key, &result);
    
    if (ret != CROSSMOOL_SUCCESS || result == NULL) {{
        fprintf(stderr, "ERROR:encrypt_sign failed: %d\\n", ret);
        return 1;
    }}
    
    // 输出格式：密文\\t签名
    printf("%s\\t%s", result->ciphertext_hex, result->signature_hex);
    
    crossmool_sm2_cipher_sig_pair_free(result);
    return 0;
}}
'''
    # 创建临时目录存放编译文件
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_c_file = os.path.join(temp_dir, "c_test_temp.c")
        temp_exe_file = os.path.join(temp_dir, "c_test_temp.exe")
        
        # 写入临时 C 文件
        with open(temp_c_file, 'w', encoding='utf-8') as f:
            f.write(c_code)
        
        try:
            # 使用 MSVC 编译器 (cl.exe) 通过 Developer Command Prompt for VS
            # 方法 1: 使用 VsDevCmd.bat 设置环境后编译
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
                # 构建 MSVC 编译命令
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
                    stdout = compile_result.stdout if compile_result.stdout else ""
                    print(f"MSVC 编译失败：{stderr}")
                    print(f"编译输出：{stdout}")
                    return None
                
                print(f"使用 MSVC 编译成功")
            else:
                # 使用 GCC (MinGW) 作为备选方案
                print("警告：找不到 VsDevCmd.bat，使用 GCC 作为备选编译器")
                gcc_path = shutil.which("gcc")
                if not gcc_path:
                    print("错误：找不到 gcc 编译器")
                    return None
                
                # GCC 编译命令 (Windows 格式)
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
                    stdout = compile_result.stdout if compile_result.stdout else ""
                    print(f"GCC 编译失败：{stderr}")
                    print(f"编译输出：{stdout}")
                    return None
                
                print(f"使用 GCC 编译成功：{gcc_path}")
            
            # 运行 C 程序，设置 DLL 路径
            # GmSSL 依赖库路径优先
            gmssl_lib_path = os.path.join(os.path.dirname(C_DLL_PATH), "..", "GmSSL", "gmssl_install", "bin")
            if os.path.exists(gmssl_lib_path):
                dll_path_str = f"{gmssl_lib_path};{C_DLL_PATH}"
            else:
                dll_path_str = C_DLL_PATH
            
            # 将临时 exe 复制到 DLL 所在目录，避免 PATH 问题
            import shutil
            temp_exe_in_dll_dir = os.path.join(C_DLL_PATH, "temp_test.exe")
            shutil.copy(temp_exe_file, temp_exe_in_dll_dir)
            
            try:
                # 使用绝对路径运行
                run_result = subprocess.run(
                    f'cmd /c "cd /d {C_DLL_PATH} && temp_test.exe"',
                    shell=True,
                    capture_output=True,
                    encoding='utf-8',
                    errors='ignore'
                )
                
                if run_result.returncode != 0:
                    stderr = run_result.stderr if run_result.stderr else "未知错误"
                    stdout = run_result.stdout if run_result.stdout else ""
                    print(f"运行失败：{stderr}")
                    print(f"运行输出：{stdout}")
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
                if os.path.exists(temp_exe_in_dll_dir):
                    os.remove(temp_exe_in_dll_dir)
            
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
                
        except Exception as e:
            print(f"编译或运行过程出错：{e}")
            return None

def main():
    """主函数"""
    print("=" * 60)
    print("C 语言 SM2 加密和签名互操作性测试 (MSVC)")
    print("=" * 60)
    
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
            result = run_c_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("C 程序执行失败")
            
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
    if len(test_cases) > 0:
        print(f"成功率：{success_count / len(test_cases) * 100:.1f}%")
    print("=" * 60)
    
    return 0 if fail_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main())