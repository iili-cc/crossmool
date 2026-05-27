#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C# 语言 SM2 加密和签名互操作性测试脚本"""

import json
import os
import sys
import subprocess
from pathlib import Path

KEYS_FILE = "testcase/keys/csharp/keys.json"
TEST_DATA_FILE = "testcase/test_data.json"
OUTPUT_DIR = "testcase/results/csharp_encrypt"
TEMP_DIR = "testcase/.csharp_temp"

def load_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def run_csharp_encrypt_sign(content, enc_public_key_hex, sign_private_key_hex):
    temp_path = Path(TEMP_DIR)
    temp_path.mkdir(exist_ok=True)
    
    test_dir = temp_path / "SM2InteropTest"
    if test_dir.exists():
        import shutil
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True)
    
    project_root = os.path.abspath(".")
    dll_path = os.path.join(project_root, "csharp", "crossmool", "src", "Crossmool.Crypto", "bin", "Debug", "net8.0", "Crossmool.Crypto.dll")
    dll_path = dll_path.replace("\\", "/")
    
    csproj_content = f"""<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="Crossmool.Crypto">
      <HintPath>{dll_path}</HintPath>
    </Reference>
    <PackageReference Include="BouncyCastle.Cryptography" Version="2.6.2" />
  </ItemGroup>
</Project>"""
    
    (test_dir / "SM2InteropTest.csproj").write_text(csproj_content, encoding='utf-8')
    
    content_file = test_dir / "input_content.bin"
    content_file.write_bytes(content.encode('utf-8'))
    
    program_content = f'''using System;
using System.IO;
using System.Text;
using Crossmool.Crypto;

class Program
{{
    static void Main(string[] args)
    {{
        try
        {{
            string content = Encoding.UTF8.GetString(File.ReadAllBytes("input_content.bin"));
            string publicKey = "{enc_public_key_hex}";
            string privateKey = "{sign_private_key_hex}";
            
            var (ciphertextHex, signatureHex) = SM2Util.encryptSign(content, publicKey, privateKey);
            
            var result = new {{
                ciphertext_hex = ciphertextHex,
                signature_hex = signatureHex
            }};
            
            var json = System.Text.Json.JsonSerializer.Serialize(result);
            Console.WriteLine(json);
        }}
        catch (Exception ex)
        {{
            Console.Error.WriteLine($"Error: {{ex.Message}}");
            Environment.Exit(1);
        }}
    }}
}}
'''
    (test_dir / "Program.cs").write_text(program_content, encoding='utf-8')
    
    try:
        build_result = subprocess.run(
            ["dotnet", "build", str(test_dir), "--configuration", "Release"],
            capture_output=True, text=True, timeout=120,
            encoding='utf-8', errors='replace'
        )
        
        if build_result.returncode != 0:
            print(f"  C# 项目构建失败:")
            print(f"  stdout: {build_result.stdout[-500:]}")
            print(f"  stderr: {build_result.stderr[-500:]}")
            return None
        
        run_result = subprocess.run(
            ["dotnet", "run", "--configuration", "Release"],
            capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='replace',
            cwd=str(test_dir)
        )
        
        if run_result.returncode != 0:
            print(f"  C# 程序执行失败:\n{run_result.stderr}\n{run_result.stdout}")
            return None
        
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
        try:
            if test_dir.exists():
                import shutil
                shutil.rmtree(test_dir)
        except:
            pass

def main():
    print("=" * 60)
    print("C# 语言 SM2 加密和签名互操作性测试")
    print("=" * 60)
    
    if not os.path.exists(KEYS_FILE):
        print(f"错误：找不到密钥文件：{KEYS_FILE}")
        sys.exit(1)
    
    if not os.path.exists(TEST_DATA_FILE):
        print(f"错误：找不到测试数据文件：{TEST_DATA_FILE}")
        sys.exit(1)
    
    print(f"\n加载密钥文件：{KEYS_FILE}")
    keys = load_json_file(KEYS_FILE)
    enc_public_key_hex = keys["encryption_public_key"]["hex"]
    sign_private_key_hex = keys["signature_private_key"]["hex"]
    print(f"  加密公钥 (Hex): {enc_public_key_hex[:40]}...")
    print(f"  签名私钥 (Hex): {sign_private_key_hex[:40]}...")
    
    print(f"\n加载测试数据：{TEST_DATA_FILE}")
    test_data = load_json_file(TEST_DATA_FILE)
    test_cases = test_data["test_cases"]
    print(f"  测试用例数量：{len(test_cases)}")
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\n输出目录：{OUTPUT_DIR}")
    
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
            result = run_csharp_encrypt_sign(plaintext, enc_public_key_hex, sign_private_key_hex)
            
            if result is None:
                raise Exception("C# 程序调用失败")
            
            ciphertext = result["ciphertext"]
            signature = result["signature"]
            
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
