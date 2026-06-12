#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Crossmool v6 Test Framework - Fixed Templates"""
import json, os, sys, subprocess
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(r"G:\workspaces\git\corssmool\crossmool")
OUTPUT_DIR = BASE_DIR / "testcase" / "output6"
LOG_FILE = BASE_DIR / "testcase" / "fix-history-20260612.log"
REPORT_FILE = BASE_DIR / "testcase" / "test_report_6.md"

TEST_MSG = "Hello, 这是跨语言国密互通性测试数据"
SM4_KEY_HEX = "0123456789abcdeffedcba9876543210"
HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
EXP_SM3 = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
EXP_SM3_HMAC = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"

SM2_KEYS = {
    "enc_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
    "enc_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
    "sig_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
    "sig_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
}

LANGUAGES = ["c", "cpp", "csharp", "java", "python", "go", "rust", "javascript"]
LANG_SHORT = {"c":"C","cpp":"CPP","csharp":"C#","java":"Java","python":"Python","go":"Go","rust":"Rust","javascript":"JS"}

fix_history = []

def log_fix(iid, desc, fpath, action):
    fix_history.append({"id":iid,"description":desc,"file":fpath,"action":action,"timestamp":datetime.now().isoformat()})
    print(f"  [FIX] {iid}: {desc}")
    # Also write fix log immediately
    write_fix_log()
    # Also write fix log immediately
    write_fix_log()

def run_cmd(cmd, cwd=None, timeout=120):
    myenv = os.environ.copy()
    myenv['JAVA_TOOL_OPTIONS'] = '-Djava.net.preferIPv4Stack=true'
    try:
        proc = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=myenv)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1

def write_fix_log():
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Crossmool Fix History - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for e in fix_history:
            f.write(f"## {e['id']}: {e['description']}\n- **File**: {e['file']}\n- **Action**: {e['action']}\n- **Time**: {e['timestamp']}\n\n")

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# Test Drivers
# ============================================================

def run_py_self():
    code = []
    code.append('import json, sys, os, binascii')
    code.append(f'sys.path.insert(0, r"{BASE_DIR}\\python\\crossmool\\src")')
    code.append('from sm2_util import SM2Util')
    code.append('from sm3_util import SM3Util')
    code.append('from sm4_util import SM4Util')
    code.append(f'MSG = """{TEST_MSG}"""')
    code.append(f'DK = {json.dumps(SM2_KEYS)}')
    code.append(f'SM4_KEY = binascii.unhexlify("{SM4_KEY_HEX}")')
    code.append(f'HMAC_KEY = binascii.unhexlify("{HMAC_KEY_HEX}")')
    code.append(f'EXP_SM3 = "{EXP_SM3}"')
    code.append(f'EXP_SM3_HMAC = "{EXP_SM3_HMAC}"')
    code.append('r = {"lang": "python"}')
    code.append('')
    code.append('# SM2 Enc/Dec')
    code.append('try:')
    code.append('    c = SM2Util.encrypt(MSG, DK["enc_pub_der_hex"], to_base64=False)')
    code.append('    r["sm2_enc"] = c')
    code.append('    d = SM2Util.decrypt(c, DK["enc_priv_der_hex"])')
    code.append('    r["sm2_enc_dec"] = "PASS" if d == MSG else "FAIL"')
    code.append('except Exception as e: r["sm2_enc_dec"] = f"FAIL: {e}"')
    code.append('')
    code.append('# SM2 Sign/Verify')
    code.append('try:')
    code.append('    sig = SM2Util.sign(MSG, DK["sig_priv_der_hex"], to_base64=False)')
    code.append('    r["sm2_sig"] = sig')
    code.append('    ok = SM2Util.verify(MSG.encode("utf-8"), DK["sig_pub_der_hex"], sig)')
    code.append('    r["sm2_sig_ver"] = "PASS" if ok else "FAIL"')
    code.append('except Exception as e: r["sm2_sig_ver"] = f"FAIL: {e}"')
    code.append('')
    code.append('# SM3')
    code.append('try:')
    code.append('    h = SM3Util.digest_str(MSG, to_base64=False)')
    code.append('    r["sm3_hash"] = h')
    code.append('    r["sm3_ok"] = h == EXP_SM3')
    code.append('except Exception as e: r["sm3_ok"] = f"FAIL: {e}"')
    code.append('')
    code.append('# SM3-HMAC')
    code.append('try:')
    code.append('    hh = SM3Util.hmac_to_hex(HMAC_KEY, MSG.encode("utf-8"))')
    code.append('    r["sm3_hmac_hash"] = hh')
    code.append('    r["sm3_hmac_ok"] = hh == EXP_SM3_HMAC')
    code.append('except Exception as e: r["sm3_hmac_ok"] = f"FAIL: {e}"')
    code.append('')
    code.append('# SM4 GCM')
    code.append('try:')
    code.append('    sc = SM4Util.encrypt_gcm(SM4_KEY, MSG.encode("utf-8"), to_base64=False)')
    code.append('    r["sm4_enc"] = sc')
    code.append('    sd = SM4Util.decrypt_gcm_to_string(SM4_KEY, sc)')
    code.append('    r["sm4_enc_dec"] = "PASS" if sd == MSG else "FAIL"')
    code.append('except Exception as e: r["sm4_enc_dec"] = f"FAIL: {e}"')
    code.append('')
    code.append('r["cross"] = {"lang":"python","msg":MSG,"sm2_enc":r.get("sm2_enc",""),"sm2_sig":r.get("sm2_sig",""),"sm4_enc":r.get("sm4_enc",""),"sm3_hash":r.get("sm3_hash",""),"sm3_hmac_hash":r.get("sm3_hmac_hash","")}')
    code.append('print(json.dumps(r, ensure_ascii=False))')
    
    fpath = OUTPUT_DIR / "py_self.py"
    fpath.write_text('\n'.join(code), encoding='utf-8')
    
    stdout, stderr, rc = run_cmd(f'python "{fpath}"')
    if rc != 0:
        print(f"  ERROR: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def run_go_self():
    go_dir = OUTPUT_DIR / "go_self"
    go_dir.mkdir(parents=True, exist_ok=True)
    
    (go_dir / "go.mod").write_text(f"module selftest\n\ngo 1.21\n\nrequire cc.iili.tools/crossmool v0.0.0\nreplace cc.iili.tools/crossmool => {BASE_DIR / 'golang' / 'crossmool'}\n")
    
    code = f"""package main

import (
        "encoding/hex"
        "encoding/json"
        "fmt"
        crossmool "cc.iili.tools/crossmool"
)

const MSG = "{TEST_MSG}"
const SM4_KEY = "{SM4_KEY_HEX}"
const HMAC_KEY = "{HMAC_KEY_HEX}"
const EXP_SM3 = "{EXP_SM3}"
const EXP_SM3_HMAC = "{EXP_SM3_HMAC}"

var DK = map[string]string{{
        "enc_pub_der":  "{SM2_KEYS['enc_pub_der_hex']}",
        "enc_priv_der": "{SM2_KEYS['enc_priv_der_hex']}",
        "sig_pub_der":  "{SM2_KEYS['sig_pub_der_hex']}",
        "sig_priv_der": "{SM2_KEYS['sig_priv_der_hex']}",
}}

func main() {{
        r := map[string]interface{{}} {{"lang": "go"}}

        // SM2 Enc/Dec
        c, err := crossmool.Encrypt(MSG, DK["enc_pub_der"], false)
        if err != nil {{
                r["sm2_enc_dec"] = "FAIL: " + err.Error()
        }} else {{
                r["sm2_enc"] = c
                d, err := crossmool.Decrypt(c, DK["enc_priv_der"])
                if err != nil {{
                        r["sm2_enc_dec"] = "FAIL: " + err.Error()
                }} else if d == MSG {{
                        r["sm2_enc_dec"] = "PASS"
                }} else {{
                        r["sm2_enc_dec"] = "FAIL"
                }}
        }}

        // SM2 Sign/Verify
        s, err := crossmool.Sign(MSG, DK["sig_priv_der"], false)
        if err != nil {{
                r["sm2_sig_ver"] = "FAIL: " + err.Error()
        }} else {{
                r["sm2_sig"] = s
                ok, _ := crossmool.Verify(MSG, DK["sig_pub_der"], s)
                if ok {{ r["sm2_sig_ver"] = "PASS" }} else {{ r["sm2_sig_ver"] = "FAIL" }}
        }}

        // SM3
        h := crossmool.DigestToStr(MSG, false)
        r["sm3_hash"] = h
        r["sm3_ok"] = (h == EXP_SM3)

        // SM3-HMAC
        hm, _ := crossmool.HMACToStr(HMAC_KEY, MSG, false)
        r["sm3_hmac_hash"] = hm
        r["sm3_hmac_ok"] = (hm == EXP_SM3_HMAC)

        // SM4 GCM
        sk, _ := hex.DecodeString(SM4_KEY)
        sc, _ := crossmool.EncryptGcm(sk, []byte(MSG), false)
        r["sm4_enc"] = sc
        sd, _ := crossmool.DecryptGcmToString(sk, sc)
        if sd == MSG {{ r["sm4_enc_dec"] = "PASS" }} else {{ r["sm4_enc_dec"] = "FAIL" }}

        // Cross data
        r["cross"] = map[string]interface{{}}{{
                "lang":           "go",
                "msg":            MSG,
                "sm2_enc":        r["sm2_enc"],
                "sm2_sig":        r["sm2_sig"],
                "sm4_enc":        r["sm4_enc"],
                "sm3_hash":       r["sm3_hash"],
                "sm3_hmac_hash":  r["sm3_hmac_hash"],
        }}

        o, _ := json.Marshal(r)
        fmt.Println(string(o))
}}
"""
    (go_dir / "main.go").write_text(code, encoding='utf-8')
    
    stdout, stderr, rc = run_cmd(f'cd "{go_dir}" && go mod tidy 2>&1 && go run .', timeout=180)
    if rc != 0:
        print(f"  go mod tidy err: {stderr}")
        stdout, stderr, rc = run_cmd(f'cd "{go_dir}" && go run .', timeout=180)
    if rc != 0:
        print(f"  ERROR: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def run_js_self():
    code = []
    code.append(f'const {{ SM2Util, SM3Util, SM4Util, hexToBytes, bytesToHex }} = require("{str(BASE_DIR / "javascript" / "crossmool" / "dist" / "index.js").replace(chr(92),"/")}");')
    code.append(f'const MSG = "{TEST_MSG}";')
    code.append(f'const SM4_KEY = "{SM4_KEY_HEX}";')
    code.append(f'const HMAC_KEY = "{HMAC_KEY_HEX}";')
    code.append(f'const EXP_SM3 = "{EXP_SM3}";')
    code.append(f'const EXP_SM3_HMAC = "{EXP_SM3_HMAC}";')
    code.append(f'const DK = {json.dumps(SM2_KEYS)};')
    code.append('const r = { lang: "javascript" };')
    code.append('')
    code.append('try {')
    code.append('    const c = SM2Util.encrypt(MSG, DK.enc_pub_der_hex, false);')
    code.append('    r.sm2_enc = c;')
    code.append('    const d = SM2Util.decrypt(c, DK.enc_priv_der_hex);')
    code.append('    r.sm2_enc_dec = (d === MSG) ? "PASS" : "FAIL";')
    code.append('} catch(e) { r.sm2_enc_dec = "FAIL: " + e.message; }')
    code.append('')
    code.append('try {')
    code.append('    const sig = SM2Util.sign(MSG, DK.sig_priv_der_hex, false);')
    code.append('    r.sm2_sig = sig;')
    code.append('    const ok = SM2Util.verify(MSG, DK.sig_pub_der_hex, sig);')
    code.append('    r.sm2_sig_ver = ok ? "PASS" : "FAIL";')
    code.append('} catch(e) { r.sm2_sig_ver = "FAIL: " + e.message; }')
    code.append('')
    code.append('try {')
    code.append('    r.sm3_hash = SM3Util.digestToHex(MSG);')
    code.append('    r.sm3_ok = (r.sm3_hash === EXP_SM3);')
    code.append('} catch(e) { r.sm3_ok = "FAIL: " + e.message; }')
    code.append('')
    code.append('try {')
    code.append('    const hm = SM3Util.hmac(hexToBytes(HMAC_KEY), MSG, false);')
    code.append('    r.sm3_hmac_hash = hm;')
    code.append('    r.sm3_hmac_ok = (hm === EXP_SM3_HMAC);')
    code.append('} catch(e) { r.sm3_hmac_ok = "FAIL: " + e.message; }')
    code.append('')
    code.append('try {')
    code.append('    const sm4Key = hexToBytes(SM4_KEY);')
    code.append('    const sc = SM4Util.encryptGcmString(MSG, sm4Key, undefined, false);')
    code.append('    r.sm4_enc = sc;')
    code.append('    const sd = SM4Util.decryptGcmToString(sc, sm4Key);')
    code.append('    r.sm4_enc_dec = (sd === MSG) ? "PASS" : "FAIL";')
    code.append('} catch(e) { r.sm4_enc_dec = "FAIL: " + e.message; }')
    code.append('')
    code.append('r.cross = { lang:"javascript", msg:MSG, sm2_enc:r.sm2_enc||"", sm2_sig:r.sm2_sig||"", sm4_enc:r.sm4_enc||"", sm3_hash:r.sm3_hash||"", sm3_hmac_hash:r.sm3_hmac_hash||"" };')
    code.append('console.log(JSON.stringify(r));')
    
    fpath = OUTPUT_DIR / "js_self.js"
    fpath.write_text('\n'.join(code), encoding='utf-8')
    
    stdout, stderr, rc = run_cmd(f'node "{fpath}"', timeout=60)
    if rc != 0:
        print(f"  ERROR: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def run_py_cross(ref_data):
    code = []
    code.append('import json, sys, os, binascii')
    code.append(f'sys.path.insert(0, r"{BASE_DIR}\\python\\crossmool\\src")')
    code.append('from sm2_util import SM2Util')
    code.append('from sm3_util import SM3Util')
    code.append('from sm4_util import SM4Util')
    code.append(f'DK = {json.dumps(SM2_KEYS)}')
    code.append(f'SM4_KEY = binascii.unhexlify("{SM4_KEY_HEX}")')
    code.append(f'HMAC_KEY = binascii.unhexlify("{HMAC_KEY_HEX}")')
    code.append('ref = json.loads(sys.stdin.read())')
    code.append('MSG = ref.get("msg", """' + TEST_MSG + '""")')
    code.append('r = {"lang":"python","consumer_of":ref.get("lang","unknown")}')
    code.append('')
    code.append('cs = ref.get("sm2_enc","")')
    code.append('if cs:')
    code.append('    try:')
    code.append('        d = SM2Util.decrypt(cs, DK["enc_priv_der_hex"])')
    code.append('        r["sm2_dec"] = "PASS" if d == MSG else "FAIL"')
    code.append('    except Exception as e: r["sm2_dec"] = f"FAIL: {e}"')
    code.append('else: r["sm2_dec"] = "SKIP"')
    code.append('')
    code.append('ss = ref.get("sm2_sig","")')
    code.append('if ss:')
    code.append('    try:')
    code.append('        ok = SM2Util.verify(MSG.encode("utf-8"), DK["sig_pub_der_hex"], ss)')
    code.append('        r["sm2_ver"] = "PASS" if ok else "FAIL"')
    code.append('    except Exception as e: r["sm2_ver"] = f"FAIL: {e}"')
    code.append('else: r["sm2_ver"] = "SKIP"')
    code.append('')
    code.append('sc = ref.get("sm4_enc","")')
    code.append('if sc:')
    code.append('    try:')
    code.append('        sd = SM4Util.decrypt_gcm_to_string(SM4_KEY, sc)')
    code.append('        r["sm4_dec"] = "PASS" if sd == MSG else "FAIL"')
    code.append('    except Exception as e: r["sm4_dec"] = f"FAIL: {e}"')
    code.append('else: r["sm4_dec"] = "SKIP"')
    code.append('')
    code.append('sh = ref.get("sm3_hash","")')
    code.append('if sh:')
    code.append('    try:')
    code.append('        h = SM3Util.digest_str(MSG, to_base64=False)')
    code.append('        r["sm3"] = "PASS" if h == sh else "FAIL"')
    code.append('    except Exception as e: r["sm3"] = f"FAIL: {e}"')
    code.append('')
    code.append('hh = ref.get("sm3_hmac_hash","")')
    code.append('if hh:')
    code.append('    try:')
    code.append('        hm = SM3Util.hmac_to_hex(HMAC_KEY, MSG.encode("utf-8"))')
    code.append('        r["sm3_hmac"] = "PASS" if hm == hh else "FAIL"')
    code.append('    except Exception as e: r["sm3_hmac"] = f"FAIL: {e}"')
    code.append('')
    code.append('print(json.dumps(r, ensure_ascii=False))')
    
    fpath = OUTPUT_DIR / "py_cross.py"
    fpath.write_text('\n'.join(code), encoding='utf-8')
    
    proc = subprocess.run(['python', str(fpath)], input=json.dumps(ref_data), capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        print(f"    err: {proc.stderr}")
        return None
    try:
        return json.loads(proc.stdout)
    except:
        return None

def run_go_cross(ref_data):
    go_dir = OUTPUT_DIR / "go_cross"
    go_dir.mkdir(parents=True, exist_ok=True)
    (go_dir / "go.mod").write_text(f"module cross_cons\n\ngo 1.21\n\nrequire cc.iili.tools/crossmool v0.0.0\nreplace cc.iili.tools/crossmool => {BASE_DIR / 'golang' / 'crossmool'}\n")
    
    code = f"""package main

import (
        "encoding/hex"
        "encoding/json"
        "fmt"
        "io"
        "os"
        crossmool "cc.iili.tools/crossmool"
)

const MSG = "{TEST_MSG}"
const SM4_KEY = "{SM4_KEY_HEX}"

var DK = map[string]string{{
        "enc_priv_der": "{SM2_KEYS['enc_priv_der_hex']}",
        "sig_pub_der":  "{SM2_KEYS['sig_pub_der_hex']}",
}}

func main() {{
        data, _ := io.ReadAll(os.Stdin)
        var ref map[string]interface{{}}
        json.Unmarshal(data, &ref)
        r := map[string]interface{{}} {{"lang": "go", "consumer_of": ref["lang"]}}

        if cs, ok := ref["sm2_enc"].(string); ok && cs != "" {{
                d, err := crossmool.Decrypt(cs, DK["enc_priv_der"])
                if err != nil {{ r["sm2_dec"] = "FAIL: " + err.Error() }} else if d == MSG {{ r["sm2_dec"] = "PASS" }} else {{ r["sm2_dec"] = "FAIL" }}
        }}

        if ss, ok := ref["sm2_sig"].(string); ok && ss != "" {{
                ok, _ := crossmool.Verify(MSG, DK["sig_pub_der"], ss)
                if ok {{ r["sm2_ver"] = "PASS" }} else {{ r["sm2_ver"] = "FAIL" }}
        }}

        if sc, ok := ref["sm4_enc"].(string); ok && sc != "" {{
                sk, _ := hex.DecodeString(SM4_KEY)
                sd, _ := crossmool.DecryptGcmToString(sk, sc)
                if sd == MSG {{ r["sm4_dec"] = "PASS" }} else {{ r["sm4_dec"] = "FAIL" }}
        }}

        if sh, ok := ref["sm3_hash"].(string); ok && sh != "" {{
                h := crossmool.DigestToStr(MSG, false)
                if h == sh {{ r["sm3"] = "PASS" }} else {{ r["sm3"] = "FAIL" }}
        }}

        if hh, ok := ref["sm3_hmac_hash"].(string); ok && hh != "" {{
                hm, _ := crossmool.HMACToStr("{HMAC_KEY_HEX}", MSG, false)
                if hm == hh {{ r["sm3_hmac"] = "PASS" }} else {{ r["sm3_hmac"] = "FAIL" }}
        }}

        o, _ := json.Marshal(r)
        fmt.Println(string(o))
}}
"""
    (go_dir / "main.go").write_text(code, encoding='utf-8')
    
    proc = subprocess.run(['go', 'run', '.'], input=json.dumps(ref_data), capture_output=True, text=True, cwd=str(go_dir), timeout=180)
    if proc.returncode != 0:
        # Try with go mod tidy first
        print(f"    go run err: {proc.stderr}")
        run_cmd(f'cd "{go_dir}" && go mod tidy 2>&1', timeout=120)
        proc = subprocess.run(['go', 'run', '.'], input=json.dumps(ref_data), capture_output=True, text=True, cwd=str(go_dir), timeout=180)
    if proc.returncode != 0:
        print(f"    go run err2: {proc.stderr}")
        return None
    try:
        return json.loads(proc.stdout)
    except:
        return None

# ============================================================
# Main
# ============================================================

def main():
    print("=" * 60)
    print("Crossmool v6 Test Framework")
    print("=" * 60)

    se = {}
    cd = {}
    cr = {}

    # Phase 1: Self-tests
    print("\n### Phase 1: Self-Tests ###")

    print("\n[Python] Self-test...")
    r = run_py_self()
    se["python"] = r if r else {"lang":"python","status":"FAIL"}
    if r and r.get("cross"):
        cd["python"] = r["cross"]
        print(f"  SM2 enc={r.get('sm2_enc_dec')} sig={r.get('sm2_sig_ver')} SM3={r.get('sm3_ok')} HMAC={r.get('sm3_hmac_ok')} SM4={r.get('sm4_enc_dec')}")

    print("\n[Go] Self-test...")
    r = run_go_self()
    se["go"] = r if r else {"lang":"go","status":"FAIL"}
    if r and r.get("cross"):
        cd["go"] = r["cross"]
        print(f"  SM2 enc={r.get('sm2_enc_dec')} sig={r.get('sm2_sig_ver')} SM3={r.get('sm3_ok')} HMAC={r.get('sm3_hmac_ok')} SM4={r.get('sm4_enc_dec')}")

    print("\n[JavaScript] Self-test...")
    r = run_js_self()
    se["javascript"] = r if r else {"lang":"javascript","status":"FAIL"}
    if r and r.get("cross"):
        cd["javascript"] = r["cross"]
        print(f"  SM2 enc={r.get('sm2_enc_dec')} sig={r.get('sm2_sig_ver')} SM3={r.get('sm3_ok')} HMAC={r.get('sm3_hmac_ok')} SM4={r.get('sm4_enc_dec')}")

    for lang in ["c", "cpp", "csharp", "java", "rust"]:
        se[lang] = {"lang": lang, "status": "NEED_BUILD"}

    # Phase 2: Cross-language tests
    print("\n\n### Phase 2: Cross-Language Tests ###")
    producers = {k: v for k, v in cd.items() if v and (v.get("sm2_enc") or v.get("sm3_hash"))}

    for plang, pdata in producers.items():
        print(f"\n--- Producer: {LANG_SHORT[plang]} ---")
        if plang != "python":
            print(f"  -> Python...")
            r = run_py_cross(pdata)
            if r:
                cr[(plang, "python")] = r
                s = {k:r[k] for k in ["sm2_dec","sm2_ver","sm3","sm3_hmac","sm4_dec"] if k in r}
                print(f"    {s}")
        if plang != "go":
            print(f"  -> Go...")
            r = run_go_cross(pdata)
            if r:
                cr[(plang, "go")] = r
                s = {k:r[k] for k in ["sm2_dec","sm2_ver","sm3","sm3_hmac","sm4_dec"] if k in r}
                print(f"    {s}")

    # Phase 3: Report
    print("\n\n### Phase 3: Report ###")
    generate_report(se, cr)
    write_fix_log()
    print(f"\nDone! Report: {REPORT_FILE}\nFix log: {LOG_FILE}")

def generate_report(se, cr):
    lines = []
    lines.append("# 跨语言国密算法互通性测试报告 v6")
    lines.append("")
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 一、各语言自测试结果")
    lines.append("")
    lines.append("| 语言 | SM2加解密 | SM2签名验签 | SM3 | SM3-HMAC | SM4 GCM | 备注 |")
    lines.append("|------|:---:|:---:|:---:|:---:|:---:|------|")

    def pv(v):
        if v == True or v == "PASS": return "✅"
        if isinstance(v, str) and v.startswith("FAIL"): return "❌"
        return "⚠️"

    for lang in LANGUAGES:
        r = se.get(lang, {})
        if not r or r.get("status") in ("NEED_BUILD", "FAIL"):
            lines.append(f"| **{LANG_SHORT[lang]}** | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | 环境未就绪 |")
            continue
        
        ed = pv(r.get("sm2_enc_dec"))
        sv = pv(r.get("sm2_sig_ver"))
        s3 = "✅" if r.get("sm3_ok") in (True, "PASS") else pv(r.get("sm3_ok"))
        sh = "✅" if r.get("sm3_hmac_ok") in (True, "PASS") else pv(r.get("sm3_hmac_ok"))
        s4 = pv(r.get("sm4_enc_dec"))
        lines.append(f"| **{LANG_SHORT[lang]}** | {ed} | {sv} | {s3} | {sh} | {s4} | |")

    lines.append("")
    lines.append("> ✅ = 实测通过 | ❌ = 实测失败 | ⚠️ = 未验证")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 二、完整测试矩阵 (8×8 = 64组合)")
    lines.append("")

    ops = [
        ("SM2加解密", "sm2_enc_dec", "sm2_dec"),
        ("SM2签名验签", "sm2_sig_ver", "sm2_ver"),
        ("SM3哈希", "sm3_ok", "sm3"),
        ("SM3-HMAC", "sm3_hmac_ok", "sm3_hmac"),
        ("SM4 GCM", "sm4_enc_dec", "sm4_dec"),
    ]

    for op_name, self_key, cross_key in ops:
        lines.append(f"### {op_name}")
        lines.append("")
        header = "| ↓/→ | " + " | ".join(LANG_SHORT[l] for l in LANGUAGES) + " |"
        sep = "|:---|" + ":---:|" * len(LANGUAGES)
        lines.append(header + "\n" + sep)

        for pl in LANGUAGES:
            row = [f"**{LANG_SHORT[pl]}**"]
            for cl in LANGUAGES:
                if pl == cl:
                    r = se.get(pl, {})
                    v = r.get(self_key)
                    if v == True or v == "PASS": row.append("⭐")
                    elif isinstance(v, str) and v.startswith("FAIL"): row.append("❌")
                    else: row.append("⚠️")
                else:
                    ce = cr.get((pl, cl), {})
                    v = ce.get(cross_key) if ce else None
                    if v == "PASS": row.append("✅")
                    elif isinstance(v, str) and v.startswith("FAIL"): row.append("❌")
                    elif isinstance(v, str) and v == "SKIP": row.append("—")
                    else: row.append("—")
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

    lines.append("---")
    lines.append("## 三、确定性算法验证")
    lines.append(f"- SM3: `{EXP_SM3}`")
    lines.append(f"- SM3-HMAC: `{EXP_SM3_HMAC}`")
    lines.append("")
    lines.append("---")
    lines.append("## 四、修复历史")
    lines.append("")
    lines.append("| ID | 问题 | 文件 | 状态 |")
    lines.append("|----|------|------|:---:|")
    for e in fix_history:
        lines.append(f"| {e['id']} | {e['description']} | {e['file']} | ✅ |")
    if fix_history:
        lines.append("## 四、修复历史")
        lines.append("")
        lines.append("| ID | 问题 | 文件 | 状态 |")
        lines.append("|----|------|------|:---:|")
        for e in fix_history:
            lines.append(f"| {e['id']} | {e['description']} | {e['file']} | ✅ |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 五、详细测试结果")
    lines.append("")
    
    # Detailed results for tested languages
    lang_labels = {"python": "Python", "go": "Go", "javascript": "JavaScript"}
    
    for lang in ["python", "go", "javascript"]:
        r = se.get(lang, {})
        if not r:
            continue
        lines.append(f"### {LANG_SHORT[lang]} 自测详细结果")
        lines.append("")
        lines.append(f"- SM2 加密解密: {r.get('sm2_enc_dec', 'N/A')}")
        lines.append(f"- SM2 签名验签: {r.get('sm2_sig_ver', 'N/A')}")
        lines.append(f"- SM3 哈希: {r.get('sm3_hash', 'N/A')} (预期: `{EXP_SM3}`)")
        lines.append(f"- SM3-HMAC: {r.get('sm3_hmac_hash', 'N/A')} (预期: `{EXP_SM3_HMAC}`)")
        lines.append(f"- SM4 GCM 加解密: {r.get('sm4_enc_dec', 'N/A')}")
        lines.append("")
    
    # Cross-language detailed
    for (pl, cl), ce in cr.items():
        if ce:
            lines.append(f"### {LANG_SHORT[pl]} → {LANG_SHORT[cl]} 跨语言验证")
            lines.append("")
            for k in ["sm2_dec", "sm2_ver", "sm3", "sm3_hmac", "sm4_dec"]:
                v = ce.get(k, "N/A")
                label = {"sm2_dec": "SM2解密", "sm2_ver": "SM2验签", "sm3": "SM3", "sm3_hmac": "SM3-HMAC", "sm4_dec": "SM4解密"}.get(k, k)
                lines.append(f"- {label}: {v}")
            lines.append("")

    lines.append("---")
    lines.append(f"\n*报告生成: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 测试框架 v6*")

    REPORT_FILE.write_text('\n'.join(lines), encoding='utf-8')
    print(f"\nReport: {REPORT_FILE}")

if __name__ == "__main__":
    main()
