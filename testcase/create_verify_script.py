#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""创建 verify_decrypt_all.py 脚本"""

import os

script_content = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
7 种语言解密验签测试脚本
"""

import json
import os
import subprocess
import sys
import shutil
import tempfile
import base64
from pathlib import Path

C_DLL_PATH = r"c/crossmool/build_msvc/Release"
C_INCLUDE_PATH = r"c/crossmool/include"
CPP_EXE_PATH = "cpp/crossmool/build/bin/Release/interoperability_test.exe"
GO_MODULE_PATH = "golang/crossmool"
JS_DIST_PATH = "javascript/crossmool/dist"
PYTHON_MODULE_PATH = "python/crossmool/src"
RUST_PROJECT_PATH = "rust/crossmool"
DOTNET_EXECUTABLE = "dotnet"

KEYS_BASE = "testcase/keys"
RESULTS_BASE = "testcase/results/verify_decrypt"
JAVA_ENCRYPT_RESULTS = "testcase/results/java_encrypt"

def load_json_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json_file(file_path, data):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def hex_to_base64_pem(hex_str, pem_type):
    der_bytes = bytes.fromhex(hex_str)
    base64_str = base64.b64encode(der_bytes).decode("ascii")
    lines = [base64_str[i:i+64] for i in range(0, len(base64_str), 64)]
    return f"-----BEGIN {pem_type}-----\n" + "\n".join(lines) + f"\n-----END {pem_type}-----\n"

def run_c_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    c_code = f"""#include <stdio.h>
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
    
    printf("%s", plaintext);
    free(plaintext);
    return 0;
}}
"""
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_c_file = os.path.join(temp_dir, "c_verify_temp.c")
        temp_exe_file = os.path.join(temp_dir, "c_verify_temp.exe")
        
        with open(temp_c_file, "w", encoding="utf-8") as f:
            f.write(c_code)
        
        try:
            vsdevcmd_path = r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
            if not os.path.exists(vsdevcmd_path):
                for alt_path in [r"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"]:
                    if os.path.exists(alt_path):
                        vsdevcmd_path = alt_path
                        break
            
            if os.path.exists(vsdevcmd_path):
                cl_cmd = f'cmd /c "call "{vsdevcmd_path}" && cl.exe /I"{C_INCLUDE_PATH}" "{temp_c_file}" /Fe"{temp_exe_file}" /link /LIBPATH:"{C_DLL_PATH}" crossmool.lib"'
                compile_result = subprocess.run(cl_cmd, shell=True, capture_output=True, encoding="gbk", errors="ignore")
                if compile_result.returncode != 0:
                    return False, f"MSVC 编译失败：{compile_result.stderr}"
            else:
                gcc_path = shutil.which("gcc")
                if not gcc_path:
                    return False, "找不到 gcc 编译器"
                gcc_cmd = f'"{gcc_path}" -I"{C_INCLUDE_PATH}" "{temp_c_file}" -o "{temp_exe_file}" -L"{C_DLL_PATH}" -lcrossmool'
                compile_result = subprocess.run(gcc_cmd, shell=True, capture_output=True, encoding="utf-8", errors="ignore")
                if compile_result.returncode != 0:
                    return False, f"GCC 编译失败：{compile_result.stderr}"
            
            temp_exe_in_dll_dir = os.path.join(C_DLL_PATH, "temp_verify.exe")
            shutil.copy(temp_exe_file, temp_exe_in_dll_dir)
            
            try:
                run_result = subprocess.run(f'cmd /c "cd /d {C_DLL_PATH} && temp_verify.exe"', shell=True, capture_output=True, encoding="utf-8", errors="ignore")
                if run_result.returncode != 0:
                    stderr = run_result.stderr if run_result.stderr else "未知错误"
                    if "ERROR:" in stderr:
                        error_msg = stderr.split("ERROR:")[1].strip().split("\n")[0]
                    else:
                        error_msg = stderr
                    return False, error_msg
                return True, run_result.stdout.strip()
            finally:
                if os.path.exists(temp_exe_in_dll_dir):
                    os.remove(temp_exe_in_dll_dir)
        except Exception as e:
            return False, f"编译或运行过程出错：{e}"

def run_cpp_verify_decrypt(ciphertext_hex, signature_hex, keys_file, exe_path):
    temp_dir = Path("testcase/.cpp_temp")
    temp_dir.mkdir(exist_ok=True)
    
    input_file = temp_dir / "verify_input.json"
    output_file = temp_dir / "verify_output.json"
    
    input_data = {"ciphertext_hex": ciphertext_hex, "signature_hex": signature_hex}
    with open(input_file, "w", encoding="utf-8") as f:
        json.dump(input_data, f)
    
    cmd = [exe_path, "verify_decrypt", str(input_file), str(keys_file), str(output_file)]
    
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30, errors="replace")
        if result.returncode != 0:
            return False, f"C++ 程序执行失败：{result.returncode}"
        if not output_file.exists():
            return False, "输出文件未生成"
        with open(output_file, "r", encoding="utf-8") as f:
            output_data = json.load(f)
        if not output_data.get("verify_result", False):
            return False, output_data.get("error", "验签失败")
        return True, output_data.get("decrypted_text", "")
    except Exception as e:
        return False, f"C++ 程序调用异常：{e}"

def run_csharp_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    temp_path = Path("testcase/.csharp_verify_temp")
    temp_path.mkdir(exist_ok=True)
    test_dir = temp_path / "SM2VerifyDecryptTest"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True)
    
    csproj_content = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
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
    
    (test_dir / "SM2VerifyDecryptTest.csproj").write_text(csproj_content, encoding="utf-8")
    input_data = {"ciphertext_hex": ciphertext_hex, "signature_hex": signature_hex, "sign_public_key_hex": sign_public_key_hex, "dec_private_key_hex": dec_private_key_hex}
    (test_dir / "input_data.json").write_text(json.dumps(input_data, ensure_ascii=False), encoding="utf-8")
    
    program_content = """using System;
using System.IO;
using System.Text.Json;
using Crossmool.Crypto;
class Program {
    static void Main(string[] args) {
        try {
            var input = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("input_data.json"));
            var decrypted = SM2Util.VerifyDecrypt(
                input.GetProperty("ciphertext_hex").GetString(),
                input.GetProperty("signature_hex").GetString(),
                input.GetProperty("sign_public_key_hex").GetString(),
                input.GetProperty("dec_private_key_hex").GetString());
            Console.WriteLine("SUCCESS:" + decrypted);
        } catch (Exception ex) {
            Console.Error.WriteLine("ERROR:" + ex.Message);
            Environment.Exit(1);
        }
    }
}"""
    (test_dir / "Program.cs").write_text(program_content, encoding="utf-8")
    
    try:
        build_result = subprocess.run([DOTNET_EXECUTABLE, "build", "-c", "Release"], cwd=str(test_dir), capture_output=True, text=True)
        if build_result.returncode != 0:
            return False, f"C# 编译失败：{build_result.stderr}"
        run_result = subprocess.run([DOTNET_EXECUTABLE, "run", "-c", "Release"], cwd=str(test_dir), capture_output=True, text=True)
        if run_result.returncode != 0:
            error_msg = run_result.stderr.strip()
            if "ERROR:" in error_msg:
                error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
            return False, error_msg
        output = run_result.stdout.strip()
        return (True, output[8:]) if output.startswith("SUCCESS:") else (False, f"未知输出格式：{output}")
    except Exception as e:
        return False, f"C# 程序调用异常：{e}"
    finally:
        try:
            shutil.rmtree(temp_path)
        except:
            pass

def run_golang_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    temp_path = Path("testcase/.golang_verify_temp")
    temp_path.mkdir(exist_ok=True)
    test_file = temp_path / "sm2_verify_test.go"
    go_code = f"""package main
import ("fmt";"os")
func main() {{
    plaintext, err := crossmool.VerifyDecrypt("{ciphertext_hex}", "{signature_hex}", "{sign_public_key_hex}", "{dec_private_key_hex}")
    if err != nil {{
        fmt.Fprintf(os.Stderr, "ERROR:%v\\n", err)
        os.Exit(1)
    }}
    fmt.Printf("SUCCESS:%s\\n", plaintext)
}}
"""
    test_file.write_text(go_code, encoding="utf-8")
    (temp_path / "go.mod").write_text("module verifytest\ngo 1.21\nreplace crossmool => ../golang/crossmool\nrequire crossmool v0.0.0\n", encoding="utf-8")
    
    try:
        run_result = subprocess.run(["go", "run", str(test_file)], capture_output=True, text=True, timeout=30, cwd=str(temp_path))
        if run_result.returncode != 0:
            error_msg = run_result.stderr.strip()
            if "ERROR:" in error_msg:
                error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
            return False, error_msg
        output = run_result.stdout.strip()
        return (True, output[8:]) if output.startswith("SUCCESS:") else (False, f"未知输出格式：{output}")
    except Exception as e:
        return False, f"Go 程序调用异常：{e}"
    finally:
        try:
            shutil.rmtree(temp_path)
        except:
            pass

def run_javascript_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    temp_js_file = "testcase/temp_sm2_verify.js"
    js_code = f"""const {{ SM2Util }} = require('{JS_DIST_PATH}/index.js');
try {{
    const decrypted = SM2Util.verifyDecrypt("{ciphertext_hex}", "{signature_hex}", "{sign_public_key_hex}", "{dec_private_key_hex}");
    console.log("SUCCESS:" + decrypted);
}} catch (error) {{
    console.error("ERROR:" + error.message);
    process.exit(1);
}}
"""
    with open(temp_js_file, "w", encoding="utf-8") as f:
        f.write(js_code)
    try:
        run_result = subprocess.run(["node", temp_js_file], capture_output=True, text=True)
        if run_result.returncode != 0:
            error_msg = run_result.stderr.strip()
            if "ERROR:" in error_msg:
                error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
            return False, error_msg
        output = run_result.stdout.strip()
        return (True, output[8:]) if output.startswith("SUCCESS:") else (False, f"未知输出格式：{output}")
    finally:
        if os.path.exists(temp_js_file):
            os.remove(temp_js_file)

def run_python_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python", "crossmool", "src"))
    try:
        from crossmool.sm2_util import SM2Util
        signature_bytes = bytes.fromhex(signature_hex)
        decrypted_bytes = SM2Util.decrypt_from_hex(ciphertext_hex, dec_private_key_hex)
        decrypted_text = decrypted_bytes.decode("utf-8")
        if not SM2Util.verify(decrypted_text.encode("utf-8"), sign_public_key_hex, signature_bytes):
            return False, "验签失败"
        return True, decrypted_text
    except Exception as e:
        return False, f"Python 模块调用异常：{e}"

def run_rust_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex):
    public_pem = hex_to_base64_pem(sign_public_key_hex, "PUBLIC KEY")
    private_pem = hex_to_base64_pem(dec_private_key_hex, "PRIVATE KEY")
    rust_code = f"""use std::process;
fn main() {{
    let public_pem = r#"{public_pem}"#;
    let private_pem = r#"{private_pem}"#;
    match crossmool::sm2::decrypt_with_private_pem_hex(&private_pem, "{ciphertext_hex}") {{
        Ok(plaintext_bytes) => {{
            let plaintext = String::from_utf8(plaintext_bytes).unwrap();
            let sig_bytes = hex::decode("{signature_hex}").unwrap();
            match crossmool::sm2::verify_with_public_pem(&public_pem, plaintext.as_bytes(), &sig_bytes) {{
                Ok(true) => println!("SUCCESS:{{}}", plaintext),
                _ => {{ eprintln!("ERROR:验签失败"); process::exit(1); }}
            }}
        }}
        Err(e) => {{ eprintln!("ERROR:解密失败：{{}}", e); process::exit(1); }}
    }}
}}
"""
    temp_path = Path("testcase/.rust_verify_temp")
    temp_path.mkdir(exist_ok=True)
    test_dir = temp_path / "rust_verify_test"
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True)
    (test_dir / "Cargo.toml").write_text('[package]\nname = "rust_verify_test"\nversion = "0.1.0"\nedition = "2021"\n[dependencies]\ncrossmool = { path = "../rust/crossmool" }\nhex = "0.4"\n', encoding="utf-8")
    (test_dir / "src").mkdir(exist_ok=True)
    (test_dir / "src" / "main.rs").write_text(rust_code, encoding="utf-8")
    
    try:
        build_result = subprocess.run(["cargo", "build", "--release"], cwd=str(test_dir), capture_output=True, text=True, timeout=120)
        if build_result.returncode != 0:
            return False, f"Rust 编译失败：{build_result.stderr}"
        exe_path = test_dir / "target" / "release" / "rust_verify_test.exe"
        if not exe_path.exists():
            exe_path = test_dir / "target" / "release" / "rust_verify_test"
        if not exe_path.exists():
            return False, "Rust 可执行文件未生成"
        run_result = subprocess.run([str(exe_path)], capture_output=True, text=True, timeout=30)
        if run_result.returncode != 0:
            error_msg = run_result.stderr.strip()
            if "ERROR:" in error_msg:
                error_msg = error_msg.split("ERROR:")[1].split("\n")[0]
            return False, error_msg
        output = run_result.stdout.strip()
        return (True, output[8:]) if output.startswith("SUCCESS:") else (False, f"未知输出格式：{output}")
    except Exception as e:
        return False, f"Rust 程序调用异常：{e}"
    finally:
        try:
            shutil.rmtree(temp_path)
        except:
            pass

def verify_language_results(language, encrypt_dir, keys):
    results = []
    success_count = 0
    fail_count = 0
    sign_public_key_hex = keys["encryption_public_key"]["hex"]
    dec_private_key_hex = keys["signature_private_key"]["hex"]
    
    if not os.path.exists(encrypt_dir):
        print(f"\n警告：加密结果目录不存在：{encrypt_dir}")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    json_files = [f for f in sorted(Path(encrypt_dir).glob("test_*.json")) if not f.name.startswith("summary")]
    if not json_files:
        print(f"\n警告：在 {encrypt_dir} 中未找到测试用例文件")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    
    print(f"\n找到 {len(json_files)} 个加密结果文件")
    
    for json_file in json_files:
        try:
            result_data = load_json_file(str(json_file))
            test_id = result_data.get("test_case_id", "unknown")
            test_name = result_data.get("test_case_name", "unknown")
            expected_plaintext = result_data.get("plaintext", "")
            ciphertext_hex = result_data.get("ciphertext_hex", "")
            signature_hex = result_data.get("signature_hex", "")
            
            print(f"\n  测试用例 {test_id}: {test_name}")
            print(f"    密文 (Hex): {ciphertext_hex[:60]}...")
            
            if language == "c":
                success, decrypted_or_error = run_c_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex)
            elif language == "cpp":
                success, decrypted_or_error = run_cpp_verify_decrypt(ciphertext_hex, signature_hex, KEYS_BASE + f"/{language}/keys.json", CPP_EXE_PATH)
            elif language == "csharp":
                success, decrypted_or_error = run_csharp_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex)
            elif language == "golang":
                success, decrypted_or_error = run_golang_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex)
            elif language == "javascript":
                success, decrypted_or_error = run_javascript_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex)
            elif language == "python":
                success, decrypted_or_error = run_python_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex)
            elif language == "rust":
                success, decrypted_or_error = run_rust_verify_decrypt(ciphertext_hex, signature_hex, sign_public_key_hex, dec_private_key_hex)
            else:
                success, decrypted_or_error = False, f"不支持的语言：{language}"
            
            if success:
                if decrypted_or_error == expected_plaintext:
                    print(f"    ✓ 验签成功，解密结果匹配")
                    success_count += 1
                    result_entry = {"test_case_id": test_id, "test_case_name": test_name, "source_language": "java", "verify_language": language, "status": "success", "expected_plaintext": expected_plaintext, "decrypted_text": decrypted_or_error, "match": True}
                else:
                    print(f"    ✗ 验签成功，但解密结果不匹配")
                    fail_count += 1
                    result_entry = {"test_case_id": test_id, "test_case_name": test_name, "source_language": "java", "verify_language": language, "status": "mismatch", "expected_plaintext": expected_plaintext, "decrypted_text": decrypted_or_error, "match": False}
            else:
                print(f"    ✗ 验签失败：{decrypted_or_error}")
                fail_count += 1
                result_entry = {"test_case_id": test_id, "test_case_name": test_name, "source_language": "java", "verify_language": language, "status": "failed", "error": decrypted_or_error, "expected_plaintext": expected_plaintext, "match": False}
            results.append(result_entry)
        except Exception as e:
            print(f"\n  处理文件 {json_file.name} 时出错：{e}")
            fail_count += 1
    
    return {"total": len(json_files), "success": success_count, "failed": fail_count, "results": results}

def main():
    print("=" * 70)
    print("7 种语言 SM2 解密验签互操作性测试")
    print("来源语言：Java (testcase/results/java_encrypt)")
    print("=" * 70)
    
    if not os.path.exists(JAVA_ENCRYPT_RESULTS):
        print(f"\n错误：找不到 Java 加密结果目录：{JAVA_ENCRYPT_RESULTS}")
        sys.exit(1)
    
    keys_file = KEYS_BASE + "/java/keys.json"
    if not os.path.exists(keys_file):
        print(f"\n错误：找不到 Java 密钥文件：{keys_file}")
        sys.exit(1)
    
    print(f"\n加载密钥文件：{keys_file}")
    keys = load_json_file(keys_file)
    print(f"  验签公钥 (Hex): {keys['encryption_public_key']['hex'][:40]}...")
    print(f"  解密私钥 (Hex): {keys['signature_private_key']['hex'][:40]}...")
    
    languages = [("c", run_c_verify_decrypt), ("cpp", run_cpp_verify_decrypt), ("csharp", run_csharp_verify_decrypt), ("golang", run_golang_verify_decrypt), ("javascript", run_javascript_verify_decrypt), ("python", run_python_verify_decrypt), ("rust", run_rust_verify_decrypt)]
    
    os.makedirs(RESULTS_BASE, exist_ok=True)
    print(f"\n验证结果输出目录：{RESULTS_BASE}")
    
    all_results = {}
    total_tests = 0
    total_success = 0
    total_failed = 0
    
    for language, lang_func in languages:
        print(f"\n{'=' * 70}")
        print(f"验证 {language.upper()} 语言")
        print(f"{'=' * 70}")
        
        lang_result = verify_language_results(language, JAVA_ENCRYPT_RESULTS, keys)
        all_results[language] = lang_result
        total_tests += lang_result["total"]
        total_success += lang_result["success"]
        total_failed += lang_result["failed"]
        
        if lang_result["total"] > 0:
            lang_output_file = os.path.join(RESULTS_BASE, f"{language}_verify_summary.json")
            save_json_file(lang_output_file, lang_result)
            print(f"\n  {language} 语言验证结果已保存到：{lang_output_file}")
            print(f"  总计：{lang_result['total']}, 成功：{lang_result['success']}, 失败：{lang_result['failed']}")
    
    summary_data = {"summary": {"total": total_tests, "success": total_success, "failed": total_failed, "success_rate": f"{total_success / total_tests * 100:.1f}%" if total_tests > 0 else "0%"}, "languages": all_results}
    summary_file = os.path.join(RESULTS_BASE, "summary.json")
    save_json_file(summary_file, summary_data)
    print(f"\n汇总结果已保存到：{summary_file}")
    
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
'''

output_path = "testcase/verify_decrypt_all.py"
with open(output_path, "w", encoding="utf-8") as f:
    f.write(script_content)

print(f"文件已创建：{output_path}")
print(f"文件大小：{len(script_content)} 字节")