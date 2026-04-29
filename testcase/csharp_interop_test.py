#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C# 语言 SM2 加密和签名互操作性测试脚本

功能:
1. 读取 testcase/keys/csharp/keys.json 中的密钥
2. 读取 testcase/test_data.json 中的测试数据
3. 通过 dotnet 命令调用 C# 程序执行加密和签名操作
4. 输出 Hex 格式的密文和签名到 testcase/results/csharp_encrypt 目录
"""

import json
import os
import sys
import subprocess
from pathlib import Path

# 配置路径
CSPROJ_PATH = "csharp/crossmool/src/Crossmool.Crypto/Crossmool.Crypto.csproj"
KEYS_FILE = "testcase/keys/csharp/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/csharp_encrypt"
TEMP_DIR = "testcase/.csharp_temp"

def load_json_file(file_path):
    """加载 JSON 文件"""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    """保存 JSON 文件"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_csharp_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    """
    通过 dotnet 命令调用 C# 程序执行加密和签名
    
    参数:
        content: 要加密和签名的内容
        enc_public_key_hex: 加密公钥 (Hex 格式)
        sign_private_key_hex: 签名私钥 (Hex 格式)
    
    返回:
        dict: 包含 ciphertext 和 signature 的字典
    """
    # 创建临时目录
    temp_path = Path(TEMP_DIR)
    temp_path.mkdir(exist_ok=True)
    
    # 创建临时 C# 测试项目
    test_dir = temp_path / "SM2InteropTest"
    if test_dir.exists():
        # 清理已存在的目录
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
    
    (test_dir / "SM2InteropTest.csproj").write_text(csproj_content, encoding='utf-8')
    
    # 将内容写入临时文件以避免转义问题
    content_file = test_dir / "input_content.txt"
    content_file.write_text(content, encoding='utf-8')
    
    # 创建 Program.cs
    program_content = '''using System;
 using System.IO;
 using System.Text;
 using Crossmool.Crypto;

 class Program
 {
     static void Main(string[] args)
     {
         try
         {
             string content = File.ReadAllText("input_content.txt", Encoding.UTF8);
             string publicKey = "''' + enc_public_key_hex + '''";
             string privateKey = "''' + sign_private_key_hex + '''";
             
             var (ciphertextHex, signatureHex) = SM2Util.encryptSign(content, publicKey, privateKey);
             
             var result = new {
                 ciphertext_hex = ciphertextHex,
                 signature_hex = signatureHex
             };
             
             var json = System.Text.Json.JsonSerializer.Serialize(result);
             Console.WriteLine(json);
         }
         catch (Exception ex)
         {
             Console.Error.WriteLine($"Error: {ex.Message}");
             Environment.Exit(1);
         }
     }
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
            print(f"  C# 项目构建失败 (返回码：{build_result.returncode}):")
            print(f"  stdout: {build_result.stdout[-500:] if len(build_result.stdout) > 500 else build_result.stdout}")
            print(f"  stderr: {build_result.stderr[-500:] if len(build_result.stderr) > 500 else build_result.stderr}")
            # 保存临时项目以便调试
            debug_dir = test_dir.parent / "debug_SM2InteropTest"
            if debug_dir.exists():
                import shutil
                try:
                    shutil.rmtree(debug_dir)
                except:
                    pass
            debug_dir.mkdir(exist_ok=True)
            import shutil
            try:
                shutil.copytree(test_dir, debug_dir)
                print(f"  临时项目已保存到：{debug_dir}")
            except Exception as e:
                print(f"  保存调试目录失败：{e}")
            return None
        
        # 运行程序
        run_result = subprocess.run(
            ["dotnet", "run", "--project", str(test_dir), "--configuration", "Release"],
            capture_output=True,
            text=True,
            timeout=30,
            encoding='utf-8',
            errors='replace',
            cwd=str(test_dir)  # 在测试项目目录下运行，以便读取 input_content.txt
        )
        
        if run_result.returncode != 0:
            print(f"  C# 程序执行失败:\n{run_result.stderr}")
            return None
        
        # 解析输出
        output_json = run_result.stdout.strip()
        result_data = json.loads(output_json)
        
        ciphertext_hex = result_data.get("ciphertext_hex")
        signature_hex = result_data.get("signature_hex")
        
        if ciphertext_hex is None or signature_hex is None:
            print(f"  加密签名结果解析失败：{output_json}")
            return None
        
        return {
            "ciphertext": ciphertext_hex,
            "signature": signature_hex
        }
        
    except subprocess.TimeoutExpired:
        print("  C# 程序执行超时")
        return None
    except Exception as e:
        print(f"  C# 程序调用异常：{e}")
        return None
    finally:
        # 清理临时目录
        try:
            if test_dir.exists():
                import shutil
                shutil.rmtree(test_dir)
        except:
            pass

def main():
    """主函数"""
    print("=" * 60)
    print("C# 语言 SM2 加密和签名互操作性测试")
    print("=" * 60)
    
    # 检查项目文件
    if not os.path.exists(CSPROJ_PATH):
        print(f"错误：找不到 C# 项目文件：{CSPROJ_PATH}")
        sys.exit(1)
    
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
            result = run_csharp_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("C# 程序调用失败")
            
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