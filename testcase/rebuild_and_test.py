#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rebuild_and_test.py
1. 用MSBuild重新编译 crossmool.dll（含修复后的sm2.c）
2. 用重新编译的DLL测试 Java -> C 互通解密/验签
3. 输出日志到 java_interop_test_20260508xx.log
"""

import subprocess
import sys
import os
import json
import shutil
import tempfile
import datetime
import ctypes

REPO_ROOT = r"G:\workspaces\git\corssmool\crossmool"
C_BUILD_DIR = os.path.join(REPO_ROOT, r"c\crossmool\build")
C_INCLUDE_DIR = os.path.join(REPO_ROOT, r"c\crossmool\include")
C_RELEASE_DIR = os.path.join(C_BUILD_DIR, "Release")
C_DLL = os.path.join(C_RELEASE_DIR, "crossmool.dll")
C_LIB = os.path.join(C_RELEASE_DIR, "crossmool.lib")
MSBUILD = r"H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
VCXPROJ = os.path.join(C_BUILD_DIR, "crossmool.vcxproj")
VSDEVCMD = r"H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"

TESTCASE_DIR = os.path.join(REPO_ROOT, "testcase")
JAVA_ENCRYPT_DIR = os.path.join(TESTCASE_DIR, r"results\java_encrypt")
KEYS_JSON = os.path.join(TESTCASE_DIR, r"keys\java\keys.json")

LOG_FILE = os.path.join(TESTCASE_DIR, f"java_interop_test_{datetime.datetime.now().strftime('%m%d%H')}.log")


def log(msg):
    ts = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{ts} {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_cmd(cmd, cwd=None, env=None, timeout=60, encoding="utf-8"):
    """运行子进程，返回 (returncode, stdout, stderr)"""
    result = subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        stdout = result.stdout.decode(encoding, errors="replace")
    except Exception:
        stdout = result.stdout.decode("gbk", errors="replace")
    try:
        stderr = result.stderr.decode(encoding, errors="replace")
    except Exception:
        stderr = result.stderr.decode("gbk", errors="replace")
    return result.returncode, stdout, stderr


def build_c_dll():
    """重新编译 crossmool.dll"""
    log("=" * 60)
    log("Step 1: 重新编译 crossmool.dll")
    log("=" * 60)

    if not os.path.exists(MSBUILD):
        log(f"ERROR: MSBuild not found at {MSBUILD}")
        return False

    if not os.path.exists(VCXPROJ):
        log(f"ERROR: vcxproj not found at {VCXPROJ}")
        return False

    # 记录修改前的DLL时间
    if os.path.exists(C_DLL):
        old_mtime = os.path.getmtime(C_DLL)
        log(f"  旧 DLL 时间: {datetime.datetime.fromtimestamp(old_mtime)}")
    else:
        old_mtime = 0
        log("  旧 DLL 不存在，将首次编译")

    cmd = [
        MSBUILD, VCXPROJ,
        "/p:Configuration=Release",
        "/p:Platform=x64",
        "/t:Build",
        "/m",
        "/nologo",
        "/p:BuildInParallel=true"
    ]
    log(f"  执行: {' '.join(cmd)}")

    rc, stdout, stderr = run_cmd(cmd, cwd=C_BUILD_DIR, timeout=180, encoding="gbk")
    log(f"  返回码: {rc}")
    if stdout.strip():
        for line in stdout.strip().split("\n")[-20:]:
            log(f"  [MSBuild] {line.rstrip()}")
    if stderr.strip():
        for line in stderr.strip().split("\n")[-10:]:
            log(f"  [MSBuild ERR] {line.rstrip()}")

    if rc != 0:
        log("ERROR: 编译失败!")
        return False

    if os.path.exists(C_DLL):
        new_mtime = os.path.getmtime(C_DLL)
        if new_mtime > old_mtime:
            log(f"  新 DLL 时间: {datetime.datetime.fromtimestamp(new_mtime)}")
            log("  编译成功!")
            return True
        else:
            log("  WARNING: DLL 时间未变化，可能没有实际重新编译")
            return True
    else:
        log("ERROR: 编译后 DLL 文件不存在!")
        return False


def compile_test_c(temp_dir, ciphertext_hex, signature_hex, sign_public_key, dec_private_key):
    """编译并运行C测试程序"""
    c_code = f'''\
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"

int main(void) {{
    const char* ciphertext  = "{ciphertext_hex}";
    const char* signature   = "{signature_hex}";
    const char* sign_pubkey = "{sign_public_key}";
    const char* dec_privkey = "{dec_private_key}";

    /* Step1: 仅测试解密（不验签），确认格式是否对 */
    {{
        char* plaintext = NULL;
        int ret = crossmool_sm2_decrypt(ciphertext, dec_privkey, "UTF-8", &plaintext);
        if (ret != 0 || plaintext == NULL) {{
            fprintf(stderr, "DECRYPT_ONLY_FAILED:%d\\n", ret);
        }} else {{
            fprintf(stderr, "DECRYPT_ONLY_OK:%s\\n", plaintext);
            free(plaintext);
        }}
    }}

    /* Step2: 仅测试验签 */
    {{
        int ret = crossmool_sm2_verify(ciphertext, "UTF-8", signature, sign_pubkey);
        if (ret == 1) {{
            fprintf(stderr, "VERIFY_ONLY_OK\\n");
        }} else {{
            fprintf(stderr, "VERIFY_ONLY_FAILED:%d\\n", ret);
        }}
    }}

    /* Step3: 联合验签+解密 */
    {{
        char* plaintext = NULL;
        int ret = crossmool_sm2_verify_decrypt(ciphertext, signature, sign_pubkey, dec_privkey, "UTF-8", &plaintext);
        if (ret != 0 || plaintext == NULL) {{
            fprintf(stderr, "VERIFY_DECRYPT_FAILED:%d\\n", ret);
            return 1;
        }}
        printf("%s", plaintext);
        free(plaintext);
    }}
    return 0;
}}
'''
    c_file = os.path.join(temp_dir, "test_interop.c")
    exe_file = os.path.join(temp_dir, "test_interop.exe")

    with open(c_file, "w", encoding="utf-8") as f:
        f.write(c_code)

    # 编译命令 (需要VsDevCmd环境)
    compile_bat = os.path.join(temp_dir, "compile.bat")
    with open(compile_bat, "w", encoding="gbk") as f:
        f.write(f'@echo off\r\n')
        f.write(f'call "{VSDEVCMD}" -arch=x64 -host_arch=x64\r\n')
        f.write(f'cl.exe /I"{C_INCLUDE_DIR}" "{c_file}" /Fe"{exe_file}" /link /LIBPATH:"{C_RELEASE_DIR}" crossmool.lib\r\n')
        f.write(f'exit /b %ERRORLEVEL%\r\n')

    rc, stdout, stderr = run_cmd(
        ["cmd.exe", "/c", compile_bat],
        cwd=temp_dir, timeout=60, encoding="gbk"
    )
    if rc != 0:
        return False, f"编译失败(rc={rc}):\n{stdout}\n{stderr}", None

    if not os.path.exists(exe_file):
        return False, f"编译后exe不存在: {exe_file}", None

    # 把exe复制到Release目录（DLL所在），避免找不到DLL
    exe_in_release = os.path.join(C_RELEASE_DIR, "test_interop_temp.exe")
    shutil.copy2(exe_file, exe_in_release)

    try:
        # 同时复制tests/Release下的gmssl.dll到Release目录（如果缺少）
        gmssl_src = os.path.join(C_BUILD_DIR, r"tests\Release\gmssl.dll")
        gmssl_dst = os.path.join(C_RELEASE_DIR, "gmssl.dll")
        if os.path.exists(gmssl_src) and not os.path.exists(gmssl_dst):
            shutil.copy2(gmssl_src, gmssl_dst)
            log("  已复制 gmssl.dll 到 Release 目录")

        rc, stdout, stderr = run_cmd(
            [exe_in_release],
            cwd=C_RELEASE_DIR, timeout=15, encoding="utf-8"
        )
        return True, stdout.strip(), stderr.strip()
    finally:
        if os.path.exists(exe_in_release):
            os.remove(exe_in_release)


def run_interop_test():
    """执行 Java 到 C 的互通测试"""
    log("=" * 60)
    log("Step 2: Java -> C 互通测试")
    log("=" * 60)

    # 加载密钥（使用Java生成的密钥）
    if not os.path.exists(KEYS_JSON):
        log(f"ERROR: 密钥文件不存在: {KEYS_JSON}")
        return False

    with open(KEYS_JSON, "r", encoding="utf-8") as f:
        keys = json.load(f)

    sign_public_key = keys["signature_public_key"]["hex"]
    dec_private_key = keys["encryption_private_key"]["hex"]
    log(f"  验签公钥(前40): {sign_public_key[:40]}...")
    log(f"  解密私钥(前40): {dec_private_key[:40]}...")

    # 查找Java加密结果
    if not os.path.exists(JAVA_ENCRYPT_DIR):
        log(f"ERROR: Java 加密结果目录不存在: {JAVA_ENCRYPT_DIR}")
        return False

    test_files = sorted([f for f in os.listdir(JAVA_ENCRYPT_DIR) if f.startswith("test_") and f.endswith(".json")])
    if not test_files:
        log("ERROR: 没有找到 Java 加密测试结果文件")
        return False

    log(f"  找到 {len(test_files)} 个测试用例")

    success_count = 0
    fail_count = 0

    with tempfile.TemporaryDirectory() as tmp:
        for tf in test_files:
            fp = os.path.join(JAVA_ENCRYPT_DIR, tf)
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)

            test_id = data.get("test_case_id", "?")
            test_name = data.get("test_case_name", "?")
            expected = data.get("plaintext", "")
            ct_hex = data.get("ciphertext_hex", "")
            sig_hex = data.get("signature_hex", "")

            log(f"\n  [{test_id}] {test_name}")
            log(f"    密文(前60): {ct_hex[:60]}...")
            log(f"    签名(前60): {sig_hex[:60]}...")
            log(f"    期望明文: {repr(expected)}")

            ok, stdout_or_err, stderr_output = compile_test_c(
                tmp, ct_hex, sig_hex, sign_public_key, dec_private_key
            )

            if not ok:
                log(f"    [FAIL] 编译/运行失败: {stdout_or_err}")
                fail_count += 1
                continue

            # 解析stderr中的调试信息
            if stderr_output:
                for line in stderr_output.split("\n"):
                    if line.strip():
                        log(f"    [DEBUG] {line.strip()}")

            # stdout是解密后的明文
            actual = stdout_or_err
            if actual == expected:
                log(f"    [OK] 解密匹配! '{actual[:50]}'")
                success_count += 1
            else:
                log(f"    [FAIL] 解密不匹配!")
                log(f"      期望: {repr(expected)}")
                log(f"      实际: {repr(actual)}")
                fail_count += 1

    log(f"\n{'=' * 60}")
    log(f"测试结果: 成功 {success_count}/{success_count+fail_count}")
    log(f"{'=' * 60}")
    return fail_count == 0


def main():
    log("=" * 70)
    log("Java -> C 互通测试 (修复 sm2_decrypt_core 后)")
    log("=" * 70)

    # 先重新编译
    if not build_c_dll():
        log("编译失败，中止测试")
        sys.exit(1)

    # 运行互通测试
    success = run_interop_test()
    
    log(f"\n日志已写入: {LOG_FILE}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
