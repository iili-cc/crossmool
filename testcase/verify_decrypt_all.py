#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
7 种语言解密验签测试脚本

功能：
1. 读取 Java 加密产生的密文和签名 HEX 文件
2. 读取 testcase/keys/java/keys.json 中的密钥
3. 分别调用各语言实现进行 SM2 解密和 SM3 验签
4. 验证解密后的明文是否与原始明文一致
5. 将各语言测试结果保存到 testcase/results/verify_decrypt/ 目录
"""

import json
import os
import subprocess
import sys
import shutil
import tempfile
import base64
import ctypes
from pathlib import Path

# 配置常量
C_DLL_PATH = r"c/crossmool/build_msvc/Release"
C_INCLUDE_PATH = r"c/crossmool/include"
CPP_EXE_PATH = "cpp/crossmool/build/bin/Release/interoperability_test.exe"
JS_DIST_PATH = "javascript/crossmool/dist"
# 使用绝对路径
DOTNET_EXECUTABLE = r"H:\Programs\dotnet-sdk-10.0.203-win-x64\dotnet.exe"
GO_EXECUTABLE = r"H:\Programs\go-1.26.2\bin\go.exe"
KEYS_BASE = "testcase/keys"
RESULTS_BASE = "testcase/results/verify_decrypt"
JAVA_ENCRYPT_RESULTS = "testcase/results/java_encrypt"

def load_json_file(fp):
    with open(fp, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json_file(fp, data):
    os.makedirs(os.path.dirname(fp), exist_ok=True)
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def hex_to_pem(h, t):
    b = base64.b64encode(bytes.fromhex(h)).decode()
    lines = [b[i:i+64] for i in range(0, len(b), 64)]
    return f"-----BEGIN {t}-----\n" + "\n".join(lines) + f"\n-----END {t}-----\n"

def run_c_verify(ct, sg, pk, sk):
    """使用 ctypes 直接调用 C DLL"""
    try:
        # 加载 DLL - 需要同时添加 GmSSL DLL 目录
        gmssl_dir = r"g:\workspaces\git\corssmool\crossmool\c\crossmool\GmSSL\build_msvc\bin"
        crossmool_dir = os.path.abspath(C_DLL_PATH)
        dll_path = os.path.join(crossmool_dir, "crossmool.dll")
        if not os.path.exists(dll_path):
            return False, f"DLL 文件不存在：{dll_path}"
        
        # 使用 os.add_dll_directory (Python 3.8+) - 必须使用绝对路径
        if hasattr(os, 'add_dll_directory'):
            os.add_dll_directory(os.path.abspath(gmssl_dir))
            os.add_dll_directory(crossmool_dir)
        
        lib = ctypes.CDLL(dll_path)
        
        # 设置函数参数和返回类型
        lib.crossmool_sm2_verify_decrypt.argtypes = [
            ctypes.c_char_p,  # ciphertext
            ctypes.c_char_p,  # signature
            ctypes.c_char_p,  # sign_public_key
            ctypes.c_char_p,  # dec_private_key
            ctypes.POINTER(ctypes.c_char_p),  # error_msg
            ctypes.POINTER(ctypes.c_char_p),  # plaintext
        ]
        lib.crossmool_sm2_verify_decrypt.restype = ctypes.c_int
        
        # 转换参数为 bytes
        ct_bytes = ct.encode('utf-8')
        sg_bytes = sg.encode('utf-8')
        pk_bytes = pk.encode('utf-8')
        sk_bytes = sk.encode('utf-8')
        
        # 调用函数
        plaintext_ptr = ctypes.c_char_p()
        error_msg_ptr = ctypes.c_char_p()
        
        ret = lib.crossmool_sm2_verify_decrypt(
            ct_bytes, sg_bytes, pk_bytes, sk_bytes,
            ctypes.byref(error_msg_ptr), ctypes.byref(plaintext_ptr)
        )
        
        if ret != 0 or plaintext_ptr.value is None:
            if error_msg_ptr.value:
                return False, error_msg_ptr.value.decode('utf-8', errors='ignore')
            return False, f"verify_decrypt failed: {ret}"
        
        plaintext = plaintext_ptr.value.decode('utf-8', errors='ignore')
        return True, plaintext
        
    except Exception as e:
        return False, str(e)

def run_cpp_verify(ct, sg, kf, ep):
    td = Path("testcase/.cpp_temp")
    td.mkdir(exist_ok=True)
    inf, ouf = td / "in.json", td / "out.json"
    with open(inf, "w", encoding='utf-8') as f:
        json.dump({"ciphertext_hex": ct, "signature_hex": sg}, f)
    try:
        cmd = [ep, "verify_decrypt", str(inf), str(kf), str(ouf)]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, errors='replace')
        if r.returncode != 0:
            stderr = r.stderr if r.stderr else "无错误输出"
            return False, f"C++ 程序执行失败 (返回码：{r.returncode}): {stderr}"
        if not ouf.exists():
            return False, "输出文件未生成"
        o = load_json_file(str(ouf))
        if o.get("verify_result"):
            return True, o.get("decrypted_text", "")
        return False, o.get("error", "验签失败")
    except Exception as e:
        return False, str(e)

def run_csharp_verify(ct, sg, pk, sk):
    # 检查 dotnet 是否可用
    try:
        r = subprocess.run(f'"{DOTNET_EXECUTABLE}" --version', shell=True, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, "dotnet 未安装或不可用"
    except Exception as e:
        return False, f"dotnet 检查失败：{e}"
    
    td = Path("testcase/.csharp_temp")
    td.mkdir(exist_ok=True)
    d = td / "SM2VerifyTest"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    csproj = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="Crossmool.Crypto">
      <HintPath>../../../csharp/crossmool/src/Crossmool.Crypto/bin/Debug/net8.0/Crossmool.Crypto.dll</HintPath>
    </Reference>
    <Reference Include="BouncyCastle.Cryptography">
      <HintPath>../../../csharp/crossmool/src/Crossmool.Crypto/bin/Debug/net8.0/BouncyCastle.Cryptography.dll</HintPath>
    </Reference>
  </ItemGroup>
</Project>"""
    (d / "SM2VerifyTest.csproj").write_text(csproj, encoding="utf-8")
    (d / "in.json").write_text(json.dumps({"ciphertext_hex": ct, "signature_hex": sg, "sign_public_key_hex": pk, "dec_private_key_hex": sk}), encoding="utf-8")
    prog = """using System;
using System.IO;
using System.Text.Json;
using Crossmool.Crypto;

class Program {
    static void Main() {
        try {
            var i = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText("in.json"));
            var ct = i.GetProperty("ciphertext_hex").GetString();
            var sg = i.GetProperty("signature_hex").GetString();
            var pk = i.GetProperty("sign_public_key_hex").GetString();
            var sk = i.GetProperty("dec_private_key_hex").GetString();
            Console.WriteLine("SUCCESS:" + SM2Util.VerifyDecrypt(ct, sg, pk, sk));
        } catch (Exception e) {
            Console.Error.WriteLine("ERROR:" + e.Message);
            Environment.Exit(1);
        }
    }
}"""
    (d / "Program.cs").write_text(prog, encoding="utf-8")
    try:
        r = subprocess.run(f'"{DOTNET_EXECUTABLE}" build -c Debug', cwd=str(d), shell=True, capture_output=True, text=True, errors='replace')
        if r.returncode != 0:
            return False, f"Build failed: {r.stderr}"
        r = subprocess.run(f'"{DOTNET_EXECUTABLE}" run -c Debug', cwd=str(d), shell=True, capture_output=True, text=True, errors='replace')
        if r.returncode != 0:
            err = r.stderr
            if "ERROR:" in err:
                err = err.split("ERROR:")[1].split("\n")[0]
            return False, err
        o = r.stdout.strip()
        if o.startswith("SUCCESS:"):
            return True, o[8:]
        return False, o
    except Exception as e:
        return False, str(e)
    finally:
        try:
            shutil.rmtree(td)
        except:
            pass

def run_go_verify(ct, sg, pk, sk):
    # 检查 go 是否可用
    try:
        r = subprocess.run(f'"{GO_EXECUTABLE}" version', shell=True, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, "Go 未安装或不可用"
    except Exception as e:
        return False, f"Go 检查失败：{e}"
    
    td = Path("testcase/.go_temp")
    td.mkdir(exist_ok=True)
    go = f'''package main

import (
\t"fmt"
\t"os"
)

func main() {{
\tciphertext := "{ct}"
\tsignature := "{sg}"
\tsignPublicKey := "{pk}"
\tdecPrivateKey := "{sk}"
\t
\tplaintext, err := crossmool.VerifyDecrypt(ciphertext, signature, signPublicKey, decPrivateKey)
\tif err != nil {{
\t\tfmt.Fprintf(os.Stderr, "ERROR:%v\\n", err)
\t\tos.Exit(1)
\t}}
\t
\tfmt.Printf("SUCCESS:%s\\n", plaintext)
}}
'''
    (td / "sm2_verify.go").write_text(go, encoding="utf-8")
    # 使用绝对路径
    golang_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "golang", "crossmool"))
    go_mod = f'''module verifytest

go 1.21

replace crossmool => {golang_path.replace('\\', '/')}

require crossmool v0.0.0
'''
    (td / "go.mod").write_text(go_mod, encoding="utf-8")
    try:
        r = subprocess.run([GO_EXECUTABLE, "run", "sm2_verify.go"], cwd=str(td), capture_output=True, text=True, timeout=30, errors='replace')
        if r.returncode != 0:
            err = r.stderr
            if "ERROR:" in err:
                err = err.split("ERROR:")[1].split("\n")[0]
            return False, err
        o = r.stdout.strip()
        if o.startswith("SUCCESS:"):
            return True, o[8:]
        return False, o
    except Exception as e:
        return False, str(e)
    finally:
        try:
            shutil.rmtree(td)
        except:
            pass

def run_js_verify(ct, sg, pk, sk):
    # 使用绝对路径
    js_dist_abs = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", JS_DIST_PATH))
    js_index = os.path.join(js_dist_abs, "index.js")
    
    tf = os.path.join(tempfile.gettempdir(), "temp_sm2_verify.js")
    js = f"""const {{ SM2Util }} = require("{js_index.replace('\\', '/')}");
try {{
    console.log("SUCCESS:" + SM2Util.verifyDecrypt("{ct}", "{sg}", "{pk}", "{sk}"));
}} catch (e) {{
    console.error("ERROR:" + e.message);
    process.exit(1);
}}
"""
    with open(tf, "w") as f:
        f.write(js)
    try:
        r = subprocess.run(["node", tf], capture_output=True, text=True)
        if r.returncode != 0:
            err = r.stderr
            if "ERROR:" in err:
                err = err.split("ERROR:")[1].split("\n")[0]
            return False, err
        o = r.stdout.strip()
        if o.startswith("SUCCESS:"):
            return True, o[8:]
        return False, o
    except Exception as e:
        return False, str(e)
    finally:
        if os.path.exists(tf):
            os.remove(tf)

def run_py_verify(ct, sg, pk, sk):
    # 使用 subprocess 方式调用 Python 脚本，避免导入问题
    py_module_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "python", "crossmool", "src"))
    td = Path("testcase/.py_temp")
    td.mkdir(exist_ok=True)
    inf = td / "input.json"
    with open(inf, "w", encoding='utf-8') as f:
        json.dump({"ciphertext_hex": ct, "signature_hex": sg, "sign_public_key_hex": pk, "dec_private_key_hex": sk}, f)
    # 修改导入方式，使用绝对路径导入
    py_code = f'''
import sys
import os
sys.path.insert(0, r"{py_module_path}")
os.chdir(r"{py_module_path}")

import json
# 直接导入 sm2_util 模块，避免相对导入问题
import sm2_util

with open(r"{inf}", "r", encoding="utf-8") as f:
    data = json.load(f)

ct = data["ciphertext_hex"]
sg = data["signature_hex"]
pk = data["sign_public_key_hex"]
sk = data["dec_private_key_hex"]

try:
    d = sm2_util.SM2Util.decrypt_from_hex(ct, sk).decode()
    if sm2_util.SM2Util.verify(d.encode(), bytes.fromhex(pk), bytes.fromhex(sg)):
        print("SUCCESS:" + d)
    else:
        print("ERROR:verify fail")
        sys.exit(1)
except Exception as e:
    print("ERROR:" + str(e))
    sys.exit(1)
'''
    pf = td / "verify.py"
    with open(pf, "w", encoding='utf-8') as f:
        f.write(py_code)
    try:
        # 使用 python 可执行文件的绝对路径
        python_exe = sys.executable
        r = subprocess.run([python_exe, str(pf)], capture_output=True, text=True, errors='replace', env=os.environ.copy())
        if r.returncode != 0:
            err = r.stderr
            if "ERROR:" in err:
                err = err.split("ERROR:")[1].split("\n")[0]
            return False, err
        o = r.stdout.strip()
        if o.startswith("SUCCESS:"):
            return True, o[8:]
        return False, o
    except Exception as e:
        return False, str(e)
    finally:
        try:
            shutil.rmtree(td)
        except:
            pass

def run_rust_verify(ct, sg, pk, sk):
    # 检查 cargo 是否可用
    try:
        r = subprocess.run("cargo --version", shell=True, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, "Rust/Cargo 未安装或不可用"
    except Exception as e:
        return False, f"Rust 检查失败：{e}"
    
    pp = hex_to_pem(pk, "PUBLIC KEY")
    pr = hex_to_pem(sk, "PRIVATE KEY")
    ct_escaped = ct.replace('\\', '\\\\').replace('"', '\\"')
    sg_escaped = sg.replace('\\', '\\\\').replace('"', '\\"')
    pp_escaped = pp.replace('\\', '\\\\').replace('"', '\\"')
    pr_escaped = pr.replace('\\', '\\\\').replace('"', '\\"')
    td = Path("testcase/.rust_temp")
    if td.exists():
        shutil.rmtree(td)
    td.mkdir(exist_ok=True)
    d = td / "rust_verify"
    d.mkdir(exist_ok=True)
    cargo = """[package]
name = "rust_verify"
version = "0.1.0"
edition = "2021"
[dependencies]
crossmool = { path = "../../rust/crossmool" }
hex = "0.4"
"""
    (d / "Cargo.toml").write_text(cargo, encoding="utf-8")
    (d / "src").mkdir(exist_ok=True)
    # 使用英文错误消息避免编码问题
    rust = f'''use std::process;

fn main() {{
    let ciphertext_hex = "{ct_escaped}";
    let signature_hex = "{sg_escaped}";
    let public_pem = r#"{pp_escaped}"#;
    let private_pem = r#"{pr_escaped}"#;

    match crossmool::sm2::decrypt_with_private_pem_hex(&private_pem, &ciphertext_hex) {{
        Ok(plaintext_bytes) => {{
            let signature_bytes = match hex::decode(&signature_hex) {{
                Ok(sig) => sig,
                Err(e) => {{
                    eprintln!("ERROR:Signature decode failed: {{}}", e);
                    process::exit(1);
                }}
            }};
            match crossmool::sm2::verify_with_public_pem(&plaintext_bytes, &signature_bytes, &public_pem) {{
                Ok(true) => {{
                    match String::from_utf8(plaintext_bytes) {{
                        Ok(text) => println!("SUCCESS:{{}}", text),
                        Err(e) => {{
                            eprintln!("ERROR:UTF-8 decode failed: {{}}", e);
                            process::exit(1);
                        }}
                    }}
                }}
                Ok(false) => {{
                    eprintln!("ERROR:Verification failed");
                    process::exit(1);
                }}
                Err(e) => {{
                    eprintln!("ERROR:Verify error: {{}}", e);
                    process::exit(1);
                }}
            }}
        }}
        Err(e) => {{
            eprintln!("ERROR:Decrypt failed: {{}}", e);
            process::exit(1);
        }}
    }}
}}
'''
    (d / "src" / "main.rs").write_text(rust, encoding="utf-8")
    try:
        # 设置 UTF-8 编码环境变量
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        env['RUSTFLAGS'] = '-C target-charset=utf-8'
        # 使用 cargo 可执行文件
        cargo_exe = shutil.which('cargo')
        if not cargo_exe:
            cargo_exe = 'cargo'
        r = subprocess.run([cargo_exe, 'build', '--release'], cwd=str(d), capture_output=True, text=True, timeout=120, errors='replace', env=env)
        if r.returncode != 0:
            return False, f"Build failed: {r.stderr}"
        e = d / "target" / "release" / "rust_verify.exe"
        if not e.exists():
            e = d / "target" / "release" / "rust_verify"
        if not e.exists():
            return False, "可执行文件未生成"
        r = subprocess.run([str(e)], capture_output=True, text=True, timeout=30, errors='replace')
        if r.returncode != 0:
            err = r.stderr
            if "ERROR:" in err:
                err = err.split("ERROR:")[1].split("\n")[0]
            return False, err
        o = r.stdout.strip()
        if o.startswith("SUCCESS:"):
            return True, o[8:]
        return False, o
    except Exception as e:
        return False, str(e)
    finally:
        try:
            shutil.rmtree(td)
        except:
            pass

def verify_lang(lang, edir, keys):
    res, sc, fc = [], 0, 0
    pk = keys["encryption_public_key"]["hex"]
    sk = keys["signature_private_key"]["hex"]
    if not os.path.exists(edir):
        print(f"\n警告：加密结果目录不存在：{edir}")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    fs = [f for f in sorted(Path(edir).glob("test_*.json")) if not f.name.startswith("summary")]
    if not fs:
        print(f"\n警告：在 {edir} 中未找到测试用例文件")
        return {"total": 0, "success": 0, "failed": 0, "results": []}
    print(f"\n找到 {len(fs)} 个加密结果文件")
    for f in fs:
        try:
            d = load_json_file(str(f))
            tid = d.get("test_case_id", "?")
            tn = d.get("test_case_name", "?")
            ep = d.get("plaintext", "")
            ct = d.get("ciphertext_hex", "")
            sg = d.get("signature_hex", "")
            print(f"\n  测试用例 {tid}: {tn}")
            print(f"    密文 (Hex): {ct[:60]}...")
            if lang == "c":
                ok, r = run_c_verify(ct, sg, pk, sk)
            elif lang == "cpp":
                ok, r = run_cpp_verify(ct, sg, KEYS_BASE + f"/{lang}/keys.json", CPP_EXE_PATH)
            elif lang == "csharp":
                ok, r = run_csharp_verify(ct, sg, pk, sk)
            elif lang == "golang":
                ok, r = run_go_verify(ct, sg, pk, sk)
            elif lang == "javascript":
                ok, r = run_js_verify(ct, sg, pk, sk)
            elif lang == "python":
                ok, r = run_py_verify(ct, sg, pk, sk)
            elif lang == "rust":
                ok, r = run_rust_verify(ct, sg, pk, sk)
            else:
                ok, r = False, "unsupported"
            if ok and r == ep:
                print(f"    [OK] 成功")
                sc += 1
                res.append({"test_case_id": tid, "test_case_name": tn, "verify_language": lang, "status": "success", "expected_plaintext": ep, "decrypted_text": r, "match": True})
            elif ok:
                print(f"    [MISMATCH] 不匹配：期望={ep[:30]} 实际={r[:30]}")
                fc += 1
                res.append({"test_case_id": tid, "test_case_name": tn, "verify_language": lang, "status": "mismatch", "expected_plaintext": ep, "decrypted_text": r, "match": False})
            else:
                print(f"    [FAIL] 失败：{r}")
                fc += 1
                res.append({"test_case_id": tid, "test_case_name": tn, "verify_language": lang, "status": "failed", "error": r, "expected_plaintext": ep, "match": False})
        except Exception as e:
            err_msg = str(e)
            print(f"\n  处理文件 {f.name} 时出错：{err_msg}")
            fc += 1
    return {"total": len(fs), "success": sc, "failed": fc, "results": res}

def main():
    print("=" * 70)
    print("7 种语言 SM2 解密验签互操作性测试")
    print("来源语言：Java (testcase/results/java_encrypt)")
    print("=" * 70)
    if not os.path.exists(JAVA_ENCRYPT_RESULTS):
        print(f"\n错误：找不到 Java 加密结果目录：{JAVA_ENCRYPT_RESULTS}")
        sys.exit(1)
    kf = KEYS_BASE + "/java/keys.json"
    if not os.path.exists(kf):
        print(f"\n错误：找不到密钥文件：{kf}")
        sys.exit(1)
    print(f"\n加载密钥文件：{kf}")
    keys = load_json_file(kf)
    print(f"  验签公钥：{keys['encryption_public_key']['hex'][:40]}...")
    print(f"  解密私钥：{keys['signature_private_key']['hex'][:40]}...")
    langs = [
        ("c", run_c_verify),
        ("cpp", run_cpp_verify),
        ("csharp", run_csharp_verify),
        ("golang", run_go_verify),
        ("javascript", run_js_verify),
        ("python", run_py_verify),
        ("rust", run_rust_verify),
    ]
    os.makedirs(RESULTS_BASE, exist_ok=True)
    print(f"\n验证结果输出目录：{RESULTS_BASE}")
    ar = {}
    tt, ts, tf = 0, 0, 0
    for lang, _ in langs:
        print(f"\n{'=' * 70}")
        print(f"验证 {lang.upper()} 语言")
        print(f"{'=' * 70}")
        lr = verify_lang(lang, JAVA_ENCRYPT_RESULTS, keys)
        ar[lang] = lr
        tt += lr["total"]
        ts += lr["success"]
        tf += lr["failed"]
        if lr["total"] > 0:
            save_json_file(os.path.join(RESULTS_BASE, f"{lang}_verify_summary.json"), lr)
            print(f"\n  {lang} 语言验证结果已保存")
            print(f"  总计：{lr['total']}, 成功：{lr['success']}, 失败：{lr['failed']}")
    save_json_file(os.path.join(RESULTS_BASE, "summary.json"), {
        "summary": {"total": tt, "success": ts, "failed": tf, "success_rate": f"{ts/tt*100:.1f}%" if tt else "0%"},
        "languages": ar
    })
    print(f"\n汇总结果已保存到：{os.path.join(RESULTS_BASE, 'summary.json')}")
    print("\n" + "=" * 70)
    print("测试总结")
    print("=" * 70)
    print(f"总测试用例：{tt}")
    print(f"成功：{ts}")
    print(f"失败：{tf}")
    if tt:
        print(f"成功率：{ts/tt*100:.1f}%")
    print("=" * 70)
    return 0 if tf == 0 else 1

if __name__ == "__main__":
    sys.exit(main())