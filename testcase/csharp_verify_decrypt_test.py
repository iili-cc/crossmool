#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C# SM2 解密验签互操作性测试脚本

功能：
1. 读取 testcase/keys/csharp/keys.json 中的解密私钥和验签公钥
2. 读取其他语言加密生成的密文和签名 JSON 文件
3. 通过 dotnet 命令调用 C# 程序执行验签和解密
4. 输出验证和解密结果到 testcase/results/csharp_verify 目录
"""

import json
import os
import sys
import subprocess
from pathlib import Path

# 配置路径
CSPROJ_PATH = "csharp/crossmool/src/Crossmool.Crypto/Crossmool.Crypto.csproj"
KEYS_FILE = "testcase/keys/csharp/keys.json"
TEST_CLASS_DIR = "testcase/csharp_test_classes"
TEMP_DIR = "testcase/.csharp_verify_temp"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_csharp_verify_decrypt(ciphertext_hex, signature_hex, plaintext, sign_public_key_hex, dec_private_key_hex):
    """
    通过 dotnet 命令调用 C# 程序执行验签和解密
    
    参数:
        ciphertext_hex: 密文 (Hex 格式)
        signature_hex: 签名 (Hex 格式)
        plaintext: 原始明文（用于验证）
        sign_public_key_hex: 验签公钥 (Hex 格式)
        dec_private_key_hex: 解密私钥 (Hex 格式)
    
    返回:
        tuple: (success: bool, decrypted_text: str or error_message: str)
    """
    # 创建临时目录
    temp_path = Path(TEMP_DIR)
    temp_path.mkdir(exist_ok=True)
    
    # 创建临时 C# 测试项目
    test_dir = temp_path / "SM2VerifyDecryptTest"
    if test_dir.exists():
        import shutil
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True)
    
    # 创建测试项目文件，使用已编译的 DLL
    csproj_content = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <ItemGroup>
    <Reference Include="Crossmool.Crypto">
      <HintPath>../../csharp/crossmool/src/Crossmool.Crypto/bin/Debug/net8.0/Crossmool.Crypto.dll</HintPath>
    </Reference>
    <Reference Include="BouncyCastle.Cryptography">
      <HintPath>../../csharp/crossmool/src/Crossmool.Crypto/bin/Debug/net8.0/BouncyCastle.Cryptography.dll</HintPath>
    </Reference>
  </ItemGroup>
</Project>"""
    
    (test_dir / "SM2VerifyDecryptTest.csproj").write_text(csproj_content, encoding='utf-8')
    
    # 将输入数据写入临时文件
    input_file = test_dir / "input_data.json"
    input_data = {
        "ciphertext_hex": ciphertext_hex,
        "signature_hex": signature_hex,
        "plaintext": plaintext,
        "sign_public_key_hex": sign_public_key_hex,
        "dec_private_key_hex": dec_private_key_hex
    }
    input_file.write_text(json.dumps(input_data, ensure_ascii=False), encoding='utf-8')
    
    # 创建 Program.cs
    program_content = '''using System;
using System.IO;
using System.Text;
using System.Text.Json;
using Crossmool.Crypto;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            var inputJson = File.ReadAllText("input_data.json");
            var input = JsonSerializer.Deserialize<InputData>(inputJson);
            
            // 先验签
            bool verifyResult = SM2Util.verify(input.Plaintext, input.SignatureHex, input.SignPublickeyHex);
            if (!verifyResult)
            {
                Console.Error.WriteLine("ERROR:Signature verification failed");
                Environment.Exit(1);
            }
            
            // 再解密
            string decryptedText = SM2Util.decryptFromHex(input.CiphertextHex, input.DecPrivatekeyHex);
            
            // 验证解密结果是否与原始明文一致
            if (decryptedText != input.Plaintext)
            {
                Console.Error.WriteLine("ERROR:Decrypted text does not match original plaintext");
                Environment.Exit(1);
            }
            
            Console.WriteLine("SUCCESS:" + decryptedText);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"ERROR:{ex.Message}");
            Environment.Exit(1);
        }
    }
}

class InputData
{
    public string CiphertextHex { get; set; }
    public string SignatureHex { get; set; }
    public string Plaintext { get; set; }
    public string SignPublickeyHex { get; set; }
    public string DecPrivatekeyHex { get; set; }
}
'''
    (test_dir / "Program.cs").write_text(program_content, encoding='utf-8')
    
    try:
        # 构建项目
        build_result = subprocess.run(
            ["dotnet", "build", str(test_dir), "--configuration", "Release"],
            capture_output=True,
            text=True,
            timeout=120,
            encoding='utf-8',
            errors='replace'
        )
        
        if build_result.returncode != 0:
            error_msg = f"C# 项目构建失败：{build_result.stderr[-200:] if len(build_result.stderr) > 200 else build_result.stderr}"
            return False, error_msg
        
        # 运行程序
        run_result = subprocess.run(
            ["dotnet", "run", "--project", str(test_dir), "--configuration", "Release"],
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='replace',
            cwd=str(test_dir)
        )
        
        if run_result.returncode != 0:
            error_msg = run_result.stderr.strip()
            if "ERROR:" in error_msg:
                error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
            return False, error_msg
        
        output = run_result.stdout.strip()
        if output.startswith("SUCCESS:"):
            decrypted_text = output[8:]  # 去掉 "SUCCESS:" 前缀
            return True, decrypted_text
        else:
            return False, f"未知输出格式：{output}"
        
    except subprocess.TimeoutExpired:
        return False, "C# 程序执行超时"
    except Exception as e:
        return False, f"C# 程序调用异常：{e}"
    finally:
        # 清理临时目录
        try:
            if test_dir.exists():
                import shutil
                shutil.rmtree(test_dir)
        except:
            pass

def verify_language_results(language, output_dir):
    """
    验证指定语言的加密结果
    
    参数:
        language: 语言名称 (c, cpp, golang, java, javascript, python, rust)
        output_dir: 该语言的加密结果目录
    
    返回:
        dict: 验证结果统计
    """
    results = []
    success_count = 0
    fail_count = 0
    
    # 加载 C# 密钥
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
            success, decrypted_or_error = run_csharp_verify_decrypt(
                ciphertext_hex, signature_hex, expected_plaintext, sign_public_key_hex, dec_private_key_hex
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
    print("C# SM2 解密验签互操作性测试")
    print("=" * 70)
    
    # 检查项目文件
    if not os.path.exists(CSPROJ_PATH):
        print(f"错误：找不到 C# 项目文件：{CSPROJ_PATH}")
        sys.exit(1)
    
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
    
    # 定义要测试的语言及其加密结果目录
    languages = [
        ("c", "testcase/results/c_encrypt"),
        ("cpp", "testcase/results/cpp_encrypt"),
        ("golang", "testcase/results/golang_encrypt"),
        ("java", "testcase/results/java_encrypt"),
        ("javascript", "testcase/results/javascript_encrypt"),
        ("python", "testcase/results/python_encrypt"),
        ("rust", "testcase/results/rust_encrypt"),
    ]
    
    # 创建输出目录
    OUTPUT_DIR = "testcase/results/csharp_verify"
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
        
        lang_result = verify_language_results(language, encrypt_dir)
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