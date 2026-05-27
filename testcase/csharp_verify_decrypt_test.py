#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""C# SM2 解密验签互操作性测试脚本"""

import json
import os
import sys
import subprocess
import base64
from pathlib import Path

KEYS_DIR = "testcase/keys"
TEMP_DIR = "testcase/.csharp_verify_temp"

def load_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json_file(file_path, data):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def get_keys_for_language(language):
    """Load keys for the specified source language.
    Returns None if the required keys (signature_public_key, encryption_private_key) are not available."""
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

def run_csharp_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    temp_path = Path(TEMP_DIR)
    temp_path.mkdir(exist_ok=True)
    
    test_dir = temp_path / "SM2VerifyDecryptTest"
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
    
    (test_dir / "SM2VerifyDecryptTest.csproj").write_text(csproj_content, encoding='utf-8')
    
    input_file = test_dir / "input_data.json"
    input_data = {
        "CiphertextHex": ciphertext_hex,
        "SignatureHex": signature_hex,
        "SignPublickeyHex": sign_public_key_hex,
        "DecPrivatekeyHex": dec_private_key_hex
    }
    input_file.write_text(json.dumps(input_data, ensure_ascii=False), encoding='utf-8')
    
    program_content = '''using System;
using System.IO;
using System.Text.Json;
using Crossmool.Crypto;

class Program
{
    static void Main(string[] args)
    {
        try
        {
            var inputJson = File.ReadAllText("input_data.json");
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var input = JsonSerializer.Deserialize<InputData>(inputJson, options);
            
            string decryptedText = SM2Util.verifyDecrypt(input.CiphertextHex, input.SignatureHex, input.SignPublickeyHex, input.DecPrivatekeyHex);
            
            // Use Base64 to preserve special characters like \\r across console output
            byte[] decryptedBytes = System.Text.Encoding.UTF8.GetBytes(decryptedText);
            Console.WriteLine("SUCCESS:" + Convert.ToBase64String(decryptedBytes));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("ERROR:" + ex.Message);
            Environment.Exit(1);
        }
    }
}

class InputData
{
    public string CiphertextHex { get; set; }
    public string SignatureHex { get; set; }
    public string SignPublickeyHex { get; set; }
    public string DecPrivatekeyHex { get; set; }
}
'''
    (test_dir / "Program.cs").write_text(program_content, encoding='utf-8')
    
    try:
        build_result = subprocess.run(
            ["dotnet", "build", str(test_dir), "--configuration", "Release"],
            capture_output=True, text=True, timeout=120,
            encoding='utf-8', errors='replace'
        )
        
        if build_result.returncode != 0:
            error_msg = f"C# project build failed: {build_result.stderr[-200:]}"
            return False, error_msg
        
        run_result = subprocess.run(
            ["dotnet", "run", "--configuration", "Release"],
            capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='replace',
            cwd=str(test_dir)
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
        return False, "C# program timeout"
    except Exception as e:
        return False, f"C# program exception: {e}"
    finally:
        try:
            if test_dir.exists():
                import shutil
                shutil.rmtree(test_dir)
        except:
            pass

def verify_language_results(language, output_dir):
    results = []
    success_count = 0
    fail_count = 0
    
    # Load keys for the source language
    keys = get_keys_for_language(language)
    if keys is None:
        print(f"\n  warn: missing required keys (signature_public_key/encryption_private_key) for language: {language}, skipping")
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
            print(f"    ciphertext (Hex): {ciphertext_hex[:60]}...")
            
            success, decrypted_or_error = run_csharp_verify_decrypt(
                ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex
            )
            
            if success:
                if decrypted_or_error == expected_plaintext:
                    print(f"    [OK] verify success, decrypt result matches")
                    print(f"    decrypted: {decrypted_or_error[:50]}{'...' if len(decrypted_or_error) > 50 else ''}")
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
    print("C# SM2 Verify-Decrypt Interop Test")
    print("=" * 70)
    
    OUTPUT_DIR = "testcase/results/csharp_verify"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"\nverify result output dir: {OUTPUT_DIR}")
    
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
        print(f"Verifying {language.upper()} encrypt results")
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
