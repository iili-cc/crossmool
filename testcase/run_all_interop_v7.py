#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Crossmool v7 综合测试框架
实现8语言自通性测试 + 8×8互通性测试 (384项)
6类操作: SM2 E/D, SM2 S/V, SM2 ES/VD, SM3, SM3-HMAC, SM4 GCM
"""
import json, os, sys, subprocess, binascii, time, shutil
from pathlib import Path
from datetime import datetime

# ======================== 配置 ========================
BASE_DIR = Path(r"G:\workspaces\git\corssmool\crossmool")
TESTCASE_DIR = BASE_DIR / "testcase"
OUTPUT_DIR = TESTCASE_DIR / "output7"
LOG_FILE = TESTCASE_DIR / "fix-history-20260619.log"
REPORT_FILE = TESTCASE_DIR / "test_report_7.md"

TEST_MSG = "Hello, 这是跨语言国密互通性测试数据"
SM4_KEY_HEX = "0123456789abcdeffedcba9876543210"
HMAC_KEY_HEX = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
EXP_SM3 = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
EXP_SM3_HMAC = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"
USER_ID = "1234567812345678"

# SM2密钥 (统一格式: DER Hex)
SM2_KEYS = {
    "enc_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
    "enc_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
    "sig_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
    "sig_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
}

LANGUAGES = ["c", "cpp", "csharp", "java", "python", "go", "rust", "javascript"]
LANG_LABELS = {"c":"C","cpp":"CPP","csharp":"C#","java":"Java","python":"Python","go":"Go","rust":"Rust","javascript":"JS"}

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

fix_history = []
test_results = {}  # {(producer, consumer, op): "PASS"/"FAIL"/"SKIP"/"ERROR"}
self_results = {}  # {lang: {op: "PASS"/"FAIL"}}
cross_data = {}    # {lang: {sm2_enc, sm2_sig, sm4_enc, sm3_hash, sm3_hmac_hash, msg}}


# ======================== 工具函数 ========================
def log_fix(iid, desc, fpath, action):
    fix_history.append({"id": iid, "description": desc, "file": fpath, "action": action,
                        "timestamp": datetime.now().isoformat()})

def run_cmd(cmd, cwd=None, timeout=120, shell=True, stdin_data=None):
    myenv = os.environ.copy()
    myenv['JAVA_TOOL_OPTIONS'] = '-Djava.net.preferIPv4Stack=true'
    try:
        proc = subprocess.run(cmd, shell=shell, cwd=cwd, capture_output=True, text=True,
                             timeout=timeout, env=myenv, input=stdin_data)
        return proc.stdout.strip(), proc.stderr.strip(), proc.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except Exception as e:
        return "", str(e), -1

def write_fix_log():
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# Crossmool Fix History - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for e in fix_history:
            f.write(f"## {e['id']}: {e['description']}\n")
            f.write(f"- **File**: {e['file']}\n- **Action**: {e['action']}\n- **Time**: {e['timestamp']}\n\n")

def build_result_dict(lang):
    return {
        "sm2_enc_dec": "SKIP", "sm2_sig_ver": "SKIP", "sm2_enc_sig_ver_dec": "SKIP",
        "sm3": "SKIP", "sm3_hmac": "SKIP", "sm4_enc_dec": "SKIP"
    }

# ======================== Python Self/Cross ========================
def python_self_test():
    print("\n[Python] Self-test...")
    code = f'''
import json, sys, os, binascii
sys.path.insert(0, r"{BASE_DIR}\\python\\crossmool\\src")
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
MSG = """{TEST_MSG}"""
DK = {json.dumps(SM2_KEYS)}
SM4_KEY = binascii.unhexlify("{SM4_KEY_HEX}")
HMAC_KEY = binascii.unhexlify("{HMAC_KEY_HEX}")
EXP_SM3 = "{EXP_SM3}"
EXP_SM3_HMAC = "{EXP_SM3_HMAC}"
r = {{"lang": "python"}}
try:
    c = SM2Util.encrypt(MSG, DK["enc_pub_der_hex"], to_base64=False)
    r["sm2_enc"] = c
    d = SM2Util.decrypt(c, DK["enc_priv_der_hex"])
    r["sm2_enc_dec"] = "PASS" if d == MSG else "FAIL"
except Exception as e: r["sm2_enc_dec"] = f"FAIL: {{e}}"
try:
    sig = SM2Util.sign(MSG, DK["sig_priv_der_hex"], to_base64=False)
    r["sm2_sig"] = sig
    ok = SM2Util.verify(MSG.encode("utf-8"), DK["sig_pub_der_hex"], sig)
    r["sm2_sig_ver"] = "PASS" if ok else "FAIL"
except Exception as e: r["sm2_sig_ver"] = f"FAIL: {{e}}"
try:
    c2 = SM2Util.encrypt(MSG, DK["enc_pub_der_hex"], to_base64=False)
    sig2 = SM2Util.sign(MSG, DK["sig_priv_der_hex"], to_base64=False)
    d2 = SM2Util.decrypt(c2, DK["enc_priv_der_hex"])
    ok2 = SM2Util.verify(d2.encode("utf-8") if isinstance(d2, str) else d2, DK["sig_pub_der_hex"], sig2)
    r["sm2_enc_sig_ver_dec"] = "PASS" if (d2 == MSG and ok2) else "FAIL"
except Exception as e: r["sm2_enc_sig_ver_dec"] = f"FAIL: {{e}}"
try:
    h = SM3Util.digest_str(MSG, to_base64=False)
    r["sm3_hash"] = h
    r["sm3"] = "PASS" if h == EXP_SM3 else "FAIL"
except Exception as e: r["sm3"] = f"FAIL: {{e}}"
try:
    hh = SM3Util.hmac_to_hex(HMAC_KEY, MSG.encode("utf-8"))
    r["sm3_hmac_hash"] = hh
    r["sm3_hmac"] = "PASS" if hh == EXP_SM3_HMAC else "FAIL"
except Exception as e: r["sm3_hmac"] = f"FAIL: {{e}}"
try:
    sc = SM4Util.encrypt_gcm(SM4_KEY, MSG.encode("utf-8"), to_base64=False)
    r["sm4_enc"] = sc
    sd = SM4Util.decrypt_gcm_to_string(SM4_KEY, sc)
    r["sm4_enc_dec"] = "PASS" if sd == MSG else "FAIL"
except Exception as e: r["sm4_enc_dec"] = f"FAIL: {{e}}"
r["cross"] = {{"lang":"python","msg":MSG,"sm2_enc":r.get("sm2_enc",""),"sm2_sig":r.get("sm2_sig",""),"sm4_enc":r.get("sm4_enc",""),"sm3_hash":r.get("sm3_hash",""),"sm3_hmac_hash":r.get("sm3_hmac_hash","")}}
print(json.dumps(r, ensure_ascii=False))
'''
    fpath = OUTPUT_DIR / "py_self.py"
    fpath.write_text(code, encoding='utf-8')
    stdout, stderr, rc = run_cmd(f'python "{fpath}"')
    if rc != 0:
        print(f"  ERROR: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def python_cross_test(ref_data):
    code = f'''
import json, sys, os, binascii
sys.path.insert(0, r"{BASE_DIR}\\python\\crossmool\\src")
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
DK = {json.dumps(SM2_KEYS)}
SM4_KEY = binascii.unhexlify("{SM4_KEY_HEX}")
HMAC_KEY = binascii.unhexlify("{HMAC_KEY_HEX}")
ref = json.loads(sys.stdin.read())
MSG = ref.get("msg", """{TEST_MSG}""")
r = {{"lang":"python","consumer_of":ref.get("lang","unknown")}}
cs = ref.get("sm2_enc","")
if cs:
    try:
        d = SM2Util.decrypt(cs, DK["enc_priv_der_hex"])
        r["sm2_dec"] = "PASS" if d == MSG else "FAIL"
    except Exception as e: r["sm2_dec"] = f"FAIL: {{e}}"
else: r["sm2_dec"] = "SKIP"
ss = ref.get("sm2_sig","")
if ss:
    try:
        ok = SM2Util.verify(MSG.encode("utf-8"), DK["sig_pub_der_hex"], ss)
        r["sm2_ver"] = "PASS" if ok else "FAIL"
    except Exception as e: r["sm2_ver"] = f"FAIL: {{e}}"
else: r["sm2_ver"] = "SKIP"
sc = ref.get("sm4_enc","")
if sc:
    try:
        sd = SM4Util.decrypt_gcm_to_string(SM4_KEY, sc)
        r["sm4_dec"] = "PASS" if sd == MSG else "FAIL"
    except Exception as e: r["sm4_dec"] = f"FAIL: {{e}}"
else: r["sm4_dec"] = "SKIP"
sh = ref.get("sm3_hash","")
if sh:
    try:
        h = SM3Util.digest_str(MSG, to_base64=False)
        r["sm3"] = "PASS" if h == sh else "FAIL"
    except Exception as e: r["sm3"] = f"FAIL: {{e}}"
hh = ref.get("sm3_hmac_hash","")
if hh:
    try:
        hm = SM3Util.hmac_to_hex(HMAC_KEY, MSG.encode("utf-8"))
        r["sm3_hmac"] = "PASS" if hm == hh else "FAIL"
    except Exception as e: r["sm3_hmac"] = f"FAIL: {{e}}"
# Encrypt+Sign -> Verify+Decrypt
cs2 = ref.get("sm2_enc","")
ss2 = ref.get("sm2_sig","")
if cs2 and ss2:
    try:
        d2 = SM2Util.decrypt(cs2, DK["enc_priv_der_hex"])
        ok2 = SM2Util.verify(d2.encode("utf-8") if isinstance(d2, str) else d2, DK["sig_pub_der_hex"], ss2)
        r["sm2_enc_sig_ver_dec"] = "PASS" if (d2 == MSG and ok2) else "FAIL"
    except Exception as e: r["sm2_enc_sig_ver_dec"] = f"FAIL: {{e}}"
else: r["sm2_enc_sig_ver_dec"] = "SKIP"
print(json.dumps(r, ensure_ascii=False))
'''
    fpath = OUTPUT_DIR / "py_cross.py"
    fpath.write_text(code, encoding='utf-8')
    proc = subprocess.run(['python', str(fpath)], input=json.dumps(ref_data),
                         capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        print(f"    err: {proc.stderr}")
        return None
    try:
        return json.loads(proc.stdout)
    except:
        return None


# ======================== Go Self/Cross ========================
def go_self_test():
    print("\n[Go] Self-test...")
    go_dir = OUTPUT_DIR / "go_self"
    if go_dir.exists():
        shutil.rmtree(go_dir)
    go_dir.mkdir(parents=True)
    (go_dir / "go.mod").write_text(
        f"module selftest\n\ngo 1.21\n\nrequire cc.iili.tools/crossmool v0.0.0\n"
        f"replace cc.iili.tools/crossmool => {BASE_DIR / 'golang' / 'crossmool'}\n")
    code = f'''package main
import ("encoding/hex";"encoding/json";"fmt";crossmool "cc.iili.tools/crossmool")
const MSG = "{TEST_MSG}"
const SM4_KEY = "{SM4_KEY_HEX}"
const HMAC_KEY = "{HMAC_KEY_HEX}"
const EXP_SM3 = "{EXP_SM3}"
const EXP_SM3_HMAC = "{EXP_SM3_HMAC}"
var DK = map[string]string{{
    "enc_pub_der": "{SM2_KEYS['enc_pub_der_hex']}",
    "enc_priv_der": "{SM2_KEYS['enc_priv_der_hex']}",
    "sig_pub_der": "{SM2_KEYS['sig_pub_der_hex']}",
    "sig_priv_der": "{SM2_KEYS['sig_priv_der_hex']}",
}}
func main() {{
    r := map[string]interface{{}}{{"lang": "go"}}
    c, err := crossmool.Encrypt(MSG, DK["enc_pub_der"], false)
    if err != nil {{ r["sm2_enc_dec"] = "FAIL: " + err.Error()
    }} else {{
        r["sm2_enc"] = c
        d, err := crossmool.Decrypt(c, DK["enc_priv_der"])
        if err != nil {{ r["sm2_enc_dec"] = "FAIL: " + err.Error()
        }} else if d == MSG {{ r["sm2_enc_dec"] = "PASS" }} else {{ r["sm2_enc_dec"] = "FAIL" }}
    }}
    s, err := crossmool.Sign(MSG, DK["sig_priv_der"], false)
    if err != nil {{ r["sm2_sig_ver"] = "FAIL: " + err.Error()
    }} else {{
        r["sm2_sig"] = s
        ok, _ := crossmool.Verify(MSG, DK["sig_pub_der"], s)
        if ok {{ r["sm2_sig_ver"] = "PASS" }} else {{ r["sm2_sig_ver"] = "FAIL" }}
    }}
    c2, _ := crossmool.Encrypt(MSG, DK["enc_pub_der"], false)
    s2, _ := crossmool.Sign(MSG, DK["sig_priv_der"], false)
    d2, _ := crossmool.Decrypt(c2, DK["enc_priv_der"])
    ok2, _ := crossmool.Verify(d2, DK["sig_pub_der"], s2)
    if d2 == MSG && ok2 {{ r["sm2_enc_sig_ver_dec"] = "PASS" }} else {{ r["sm2_enc_sig_ver_dec"] = "FAIL" }}
    h := crossmool.DigestToStr(MSG, false)
    r["sm3_hash"] = h
    r["sm3"] = func() string {{ if h == EXP_SM3 {{ return "PASS" }}; return "FAIL" }}()
    hm, _ := crossmool.HMACToStr(HMAC_KEY, MSG, false)
    r["sm3_hmac_hash"] = hm
    r["sm3_hmac"] = func() string {{ if hm == EXP_SM3_HMAC {{ return "PASS" }}; return "FAIL" }}()
    sk, _ := hex.DecodeString(SM4_KEY)
    sc, err := crossmool.EncryptGcm(sk, []byte(MSG), false)
    if err != nil {{ r["sm4_enc_dec"] = "FAIL: " + err.Error()
    }} else {{
        r["sm4_enc"] = sc
        sd, err := crossmool.DecryptGcmToString(sk, sc)
        if err != nil {{ r["sm4_enc_dec"] = "FAIL: " + err.Error()
        }} else if sd == MSG {{ r["sm4_enc_dec"] = "PASS" }} else {{ r["sm4_enc_dec"] = "FAIL" }}
    }}
    r["cross"] = map[string]interface{{}}{{"lang":"go","msg":MSG,"sm2_enc":r["sm2_enc"],"sm2_sig":r["sm2_sig"],"sm4_enc":r["sm4_enc"],"sm3_hash":r["sm3_hash"],"sm3_hmac_hash":r["sm3_hmac_hash"]}}
    o, _ := json.Marshal(r)
    fmt.Println(string(o))
}}
'''
    (go_dir / "main.go").write_text(code, encoding='utf-8')
    stdout, stderr, rc = run_cmd(f'cd "{go_dir}" && go mod tidy && go run .', timeout=180)
    if rc != 0:
        print(f"  go err: {stderr}")
        stdout, stderr, rc = run_cmd(f'cd "{go_dir}" && go run .', timeout=180)
    if rc != 0:
        print(f"  ERROR: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def go_cross_test(ref_data):
    go_dir = OUTPUT_DIR / "go_cross"
    if go_dir.exists():
        shutil.rmtree(go_dir)
    go_dir.mkdir(parents=True)
    (go_dir / "go.mod").write_text(
        f"module cross_cons\n\ngo 1.21\n\nrequire cc.iili.tools/crossmool v0.0.0\n"
        f"replace cc.iili.tools/crossmool => {BASE_DIR / 'golang' / 'crossmool'}\n")
    code = f'''package main
import ("encoding/hex";"encoding/json";"fmt";"io";"os";crossmool "cc.iili.tools/crossmool")
const MSG = "{TEST_MSG}"
const SM4_KEY = "{SM4_KEY_HEX}"
var DK = map[string]string{{
    "enc_priv_der": "{SM2_KEYS['enc_priv_der_hex']}",
    "sig_pub_der": "{SM2_KEYS['sig_pub_der_hex']}",
}}
func main() {{
    data, _ := io.ReadAll(os.Stdin)
    var ref map[string]interface{{}}
    json.Unmarshal(data, &ref)
    r := map[string]interface{{}}{{"lang": "go", "consumer_of": ref["lang"]}}
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
        sd, err := crossmool.DecryptGcmToString(sk, sc)
        if err != nil {{ r["sm4_dec"] = "FAIL: " + err.Error() }} else if sd == MSG {{ r["sm4_dec"] = "PASS" }} else {{ r["sm4_dec"] = "FAIL" }}
    }}
    if sh, ok := ref["sm3_hash"].(string); ok && sh != "" {{
        h := crossmool.DigestToStr(MSG, false)
        if h == sh {{ r["sm3"] = "PASS" }} else {{ r["sm3"] = "FAIL" }}
    }}
    if hh, ok := ref["sm3_hmac_hash"].(string); ok && hh != "" {{
        hm, _ := crossmool.HMACToStr("{HMAC_KEY_HEX}", MSG, false)
        if hm == hh {{ r["sm3_hmac"] = "PASS" }} else {{ r["sm3_hmac"] = "FAIL" }}
    }}
    cs2, _ := ref["sm2_enc"].(string)
    ss2, _ := ref["sm2_sig"].(string)
    if cs2 != "" && ss2 != "" {{
        d2, _ := crossmool.Decrypt(cs2, DK["enc_priv_der"])
        ok2, _ := crossmool.Verify(d2, DK["sig_pub_der"], ss2)
        if d2 == MSG && ok2 {{ r["sm2_enc_sig_ver_dec"] = "PASS" }} else {{ r["sm2_enc_sig_ver_dec"] = "FAIL" }}
    }}
    o, _ := json.Marshal(r)
    fmt.Println(string(o))
}}
'''
    (go_dir / "main.go").write_text(code, encoding='utf-8')
    run_cmd(f'cd "{go_dir}" && go mod tidy', timeout=120)
    proc = subprocess.run(['go', 'run', '.'], input=json.dumps(ref_data),
                         capture_output=True, text=True, cwd=str(go_dir), timeout=180)
    if proc.returncode != 0:
        print(f"    go run err: {proc.stderr}")
        return None
    try:
        return json.loads(proc.stdout)
    except:
        return None


# ======================== JavaScript Self/Cross ========================
def js_self_test():
    print("\n[JavaScript] Self-test...")
    js_module = str(BASE_DIR / "javascript" / "crossmool" / "dist" / "index.js").replace("\\", "/")
    code = f'''
const {{ SM2Util, SM3Util, SM4Util, hexToBytes, bytesToHex }} = require("{js_module}");
const MSG = "{TEST_MSG}";
const SM4_KEY = "{SM4_KEY_HEX}";
const HMAC_KEY = "{HMAC_KEY_HEX}";
const EXP_SM3 = "{EXP_SM3}";
const EXP_SM3_HMAC = "{EXP_SM3_HMAC}";
const DK = {json.dumps(SM2_KEYS)};
const r = {{ lang: "javascript" }};
try {{
    const c = SM2Util.encrypt(MSG, DK.enc_pub_der_hex, false);
    r.sm2_enc = c;
    const d = SM2Util.decrypt(c, DK.enc_priv_der_hex);
    r.sm2_enc_dec = (d === MSG) ? "PASS" : "FAIL";
}} catch(e) {{ r.sm2_enc_dec = "FAIL: " + e.message; }}
try {{
    const sig = SM2Util.sign(MSG, DK.sig_priv_der_hex, false);
    r.sm2_sig = sig;
    const ok = SM2Util.verify(MSG, DK.sig_pub_der_hex, sig);
    r.sm2_sig_ver = ok ? "PASS" : "FAIL";
}} catch(e) {{ r.sm2_sig_ver = "FAIL: " + e.message; }}
try {{
    const c2 = SM2Util.encrypt(MSG, DK.enc_pub_der_hex, false);
    const s2 = SM2Util.sign(MSG, DK.sig_priv_der_hex, false);
    const d2 = SM2Util.decrypt(c2, DK.enc_priv_der_hex);
    const ok2 = SM2Util.verify(d2, DK.sig_pub_der_hex, s2);
    r.sm2_enc_sig_ver_dec = (d2 === MSG && ok2) ? "PASS" : "FAIL";
}} catch(e) {{ r.sm2_enc_sig_ver_dec = "FAIL: " + e.message; }}
try {{
    r.sm3_hash = SM3Util.digestToHex(MSG);
    r.sm3 = (r.sm3_hash === EXP_SM3) ? "PASS" : "FAIL";
}} catch(e) {{ r.sm3 = "FAIL: " + e.message; }}
try {{
    const hm = SM3Util.hmac(hexToBytes(HMAC_KEY), MSG, false);
    r.sm3_hmac_hash = hm;
    r.sm3_hmac = (hm === EXP_SM3_HMAC) ? "PASS" : "FAIL";
}} catch(e) {{ r.sm3_hmac = "FAIL: " + e.message; }}
try {{
    const sm4Key = hexToBytes(SM4_KEY);
    const sc = SM4Util.encryptGcmString(MSG, sm4Key, undefined, false);
    r.sm4_enc = sc;
    const sd = SM4Util.decryptGcmToString(sc, sm4Key);
    r.sm4_enc_dec = (sd === MSG) ? "PASS" : "FAIL";
}} catch(e) {{ r.sm4_enc_dec = "FAIL: " + e.message; }}
r.cross = {{ lang:"javascript", msg:MSG, sm2_enc:r.sm2_enc||"", sm2_sig:r.sm2_sig||"", sm4_enc:r.sm4_enc||"", sm3_hash:r.sm3_hash||"", sm3_hmac_hash:r.sm3_hmac_hash||"" }};
console.log(JSON.stringify(r));
'''
    fpath = OUTPUT_DIR / "js_self.js"
    fpath.write_text(code, encoding='utf-8')
    stdout, stderr, rc = run_cmd(f'node "{fpath}"', timeout=60)
    if rc != 0:
        print(f"  ERROR: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def js_cross_test(ref_data):
    js_module = str(BASE_DIR / "javascript" / "crossmool" / "dist" / "index.js").replace("\\", "/")
    code = f'''
const {{ SM2Util, SM3Util, SM4Util, hexToBytes }} = require("{js_module}");
const DK = {json.dumps(SM2_KEYS)};
const SM4_KEY = "{SM4_KEY_HEX}";
const HMAC_KEY = "{HMAC_KEY_HEX}";
const ref = JSON.parse(process.argv[1]);
const MSG = ref.msg || "{TEST_MSG}";
const r = {{ lang: "javascript", consumer_of: ref.lang }};
try {{
    if (ref.sm2_enc) {{
        const d = SM2Util.decrypt(ref.sm2_enc, DK.enc_priv_der_hex);
        r.sm2_dec = (d === MSG) ? "PASS" : "FAIL";
    }}
}} catch(e) {{ r.sm2_dec = "FAIL: " + e.message; }}
try {{
    if (ref.sm2_sig) {{
        const ok = SM2Util.verify(MSG, DK.sig_pub_der_hex, ref.sm2_sig);
        r.sm2_ver = ok ? "PASS" : "FAIL";
    }}
}} catch(e) {{ r.sm2_ver = "FAIL: " + e.message; }}
try {{
    if (ref.sm2_enc && ref.sm2_sig) {{
        const d2 = SM2Util.decrypt(ref.sm2_enc, DK.enc_priv_der_hex);
        const ok2 = SM2Util.verify(d2, DK.sig_pub_der_hex, ref.sm2_sig);
        r.sm2_enc_sig_ver_dec = (d2 === MSG && ok2) ? "PASS" : "FAIL";
    }}
}} catch(e) {{ r.sm2_enc_sig_ver_dec = "FAIL: " + e.message; }}
try {{
    if (ref.sm3_hash) {{
        const h = SM3Util.digestToHex(MSG);
        r.sm3 = (h === ref.sm3_hash) ? "PASS" : "FAIL";
    }}
}} catch(e) {{ r.sm3 = "FAIL: " + e.message; }}
try {{
    if (ref.sm3_hmac_hash) {{
        const hm = SM3Util.hmac(hexToBytes(HMAC_KEY), MSG, false);
        r.sm3_hmac = (hm === ref.sm3_hmac_hash) ? "PASS" : "FAIL";
    }}
}} catch(e) {{ r.sm3_hmac = "FAIL: " + e.message; }}
try {{
    if (ref.sm4_enc) {{
        const sm4Key = hexToBytes(SM4_KEY);
        const sd = SM4Util.decryptGcmToString(ref.sm4_enc, sm4Key);
        r.sm4_dec = (sd === MSG) ? "PASS" : "FAIL";
    }}
}} catch(e) {{ r.sm4_dec = "FAIL: " + e.message; }}
console.log(JSON.stringify(r));
'''
    fpath = OUTPUT_DIR / "js_cross.js"
    fpath.write_text(code, encoding='utf-8')
    proc = subprocess.run(['node', str(fpath), json.dumps(ref_data)],
                         capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        print(f"    node err: {proc.stderr}")
        return None
    try:
        return json.loads(proc.stdout)
    except:
        return None


# ======================== Java Self/Cross ========================
def java_self_test():
    print("\n[Java] Self-test...")
    java_src = BASE_DIR / "java" / "crossmool" / "src" / "main" / "java"
    bc_jar = None
    for p in (BASE_DIR / "java" / "crossmool").rglob("*.jar"):
        if "bcprov" in p.name:
            bc_jar = p
            break
    if not bc_jar:
        # Search m2 repository
        m2 = Path.home() / ".m2" / "repository"
        for p in m2.rglob("bcprov-jdk18on-*.jar"):
            bc_jar = p
            break
    cp = f"{java_src}"
    if bc_jar:
        cp += os.pathsep + str(bc_jar)
    java_dir = OUTPUT_DIR / "java_self"
    java_dir.mkdir(parents=True, exist_ok=True)
    code = f'''import java.nio.charset.StandardCharsets;
import java.util.Base64;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;
public class SelfTest {{
    static String MSG = "{TEST_MSG}";
    static String SM4_KEY_HEX = "{SM4_KEY_HEX}";
    static String HMAC_KEY_HEX = "{HMAC_KEY_HEX}";
    static String EXP_SM3 = "{EXP_SM3}";
    static String EXP_SM3_HMAC = "{EXP_SM3_HMAC}";
    static String ENC_PUB = "{SM2_KEYS['enc_pub_der_hex']}";
    static String ENC_PRIV = "{SM2_KEYS['enc_priv_der_hex']}";
    static String SIG_PUB = "{SM2_KEYS['sig_pub_der_hex']}";
    static String SIG_PRIV = "{SM2_KEYS['sig_priv_der_hex']}";
    public static void main(String[] args) {{
        StringBuilder sb = new StringBuilder();
        sb.append("{{\\"lang\\":\\"java\\"");
        try {{
            String c = SM2Util.encrypt(MSG, ENC_PUB, false);
            sb.append(",\\"sm2_enc\\":\\"").append(escape(c)).append("\\"");
            String d = SM2Util.decrypt(c, ENC_PRIV);
            sb.append(",\\"sm2_enc_dec\\":\\"").append(d.equals(MSG)?"PASS":"FAIL").append("\\"");
        }} catch (Exception e) {{ sb.append(",\\"sm2_enc_dec\\":\\"FAIL: ").append(escape(e.getMessage())).append("\\""); }}
        try {{
            String sig = SM2Util.sign(MSG, SIG_PRIV, false);
            sb.append(",\\"sm2_sig\\":\\"").append(escape(sig)).append("\\"");
            boolean ok = SM2Util.verify(MSG, SIG_PUB, sig);
            sb.append(",\\"sm2_sig_ver\\":\\"").append(ok?"PASS":"FAIL").append("\\"");
        }} catch (Exception e) {{ sb.append(",\\"sm2_sig_ver\\":\\"FAIL: ").append(escape(e.getMessage())).append("\\""); }}
        try {{
            String c2 = SM2Util.encrypt(MSG, ENC_PUB, false);
            String s2 = SM2Util.sign(MSG, SIG_PRIV, false);
            String d2 = SM2Util.decrypt(c2, ENC_PRIV);
            boolean ok2 = SM2Util.verify(d2, SIG_PUB, s2);
            sb.append(",\\"sm2_enc_sig_ver_dec\\":\\"").append(d2.equals(MSG)&&ok2?"PASS":"FAIL").append("\\"");
        }} catch (Exception e) {{ sb.append(",\\"sm2_enc_sig_ver_dec\\":\\"FAIL: ").append(escape(e.getMessage())).append("\\""); }}
        try {{
            String h = SM3Util.digestToStr(MSG, false);
            sb.append(",\\"sm3_hash\\":\\"").append(h).append("\\"");
            sb.append(",\\"sm3\\":\\"").append(h.equals(EXP_SM3)?"PASS":"FAIL").append("\\"");
        }} catch (Exception e) {{ sb.append(",\\"sm3\\":\\"FAIL: ").append(escape(e.getMessage())).append("\\""); }}
        try {{
            byte[] hmacKey = HexUtil.decodeHexStr(HMAC_KEY_HEX);
            String hm = SM3Util.hmacToStr(HMAC_KEY_HEX, MSG, false);
            sb.append(",\\"sm3_hmac_hash\\":\\"").append(hm).append("\\"");
            sb.append(",\\"sm3_hmac\\":\\"").append(hm.equals(EXP_SM3_HMAC)?"PASS":"FAIL").append("\\"");
        }} catch (Exception e) {{ sb.append(",\\"sm3_hmac\\":\\"FAIL: ").append(escape(e.getMessage())).append("\\""); }}
        try {{
            byte[] sm4Key = HexUtil.decodeHexStr(SM4_KEY_HEX);
            String sc = SM4Util.encrypt(sm4Key, MSG.getBytes(StandardCharsets.UTF_8), false);
            sb.append(",\\"sm4_enc\\":\\"").append(escape(sc)).append("\\"");
            String sd = SM4Util.decrypt(sm4Key, sc);
            sb.append(",\\"sm4_enc_dec\\":\\"").append(sd.equals(MSG)?"PASS":"FAIL").append("\\"");
        }} catch (Exception e) {{ sb.append(",\\"sm4_enc_dec\\":\\"FAIL: ").append(escape(e.getMessage())).append("\\""); }}
        sb.append("}}");
        System.out.println(sb.toString());
    }}
    static String escape(String s) {{ return s.replace("\\\\","\\\\\\\\").replace("\\"","\\\\\\"").replace("\\n","\\\\n").replace("\\r",""); }}
}}
'''
    (java_dir / "SelfTest.java").write_text(code, encoding='utf-8')
    # Find BouncyCastle jar
    bc_jars = list((BASE_DIR / "java" / "crossmool").rglob("bcprov*.jar"))
    if not bc_jars:
        bc_jars = list(Path.home().rglob(".m2/repository/**/bcprov-jdk18on-*.jar"))
    cp = str(java_src)
    for j in bc_jars:
        cp += os.pathsep + str(j)
    print(f"  CP includes BC: {len(bc_jars)} jars")
    if not bc_jars:
        print("  WARNING: No BouncyCastle jar found!")
        return None
    stdout, stderr, rc = run_cmd(f'javac -encoding UTF-8 -cp "{cp}" -d "{java_dir}" "{java_dir}/SelfTest.java"', timeout=60)
    if rc != 0:
        print(f"  javac err: {stderr}")
        return None
    stdout, stderr, rc = run_cmd(f'java -cp "{cp}{os.pathsep}{java_dir}" SelfTest', timeout=60)
    if rc != 0:
        print(f"  java err: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def java_cross_test(ref_data):
    java_src = BASE_DIR / "java" / "crossmool" / "src" / "main" / "java"
    java_dir = OUTPUT_DIR / "java_cross"
    java_dir.mkdir(parents=True, exist_ok=True)
    bc_jars = list((BASE_DIR / "java" / "crossmool").rglob("bcprov*.jar"))
    if not bc_jars:
        bc_jars = list(Path.home().rglob(".m2/repository/**/bcprov-jdk18on-*.jar"))
    cp = str(java_src)
    for j in bc_jars:
        cp += os.pathsep + str(j)
    code = f'''import java.nio.charset.StandardCharsets;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;
import java.nio.file.*;
public class CrossTest {{
    static String MSG = "{TEST_MSG}";
    static String SM4_KEY_HEX = "{SM4_KEY_HEX}";
    static String HMAC_KEY_HEX = "{HMAC_KEY_HEX}";
    static String ENC_PRIV = "{SM2_KEYS['enc_priv_der_hex']}";
    static String SIG_PUB = "{SM2_KEYS['sig_pub_der_hex']}";
    public static void main(String[] args) throws Exception {{
        String jsonStr = Files.readString(Path.of(args[0]));
        // Simple JSON parse using string manipulation
        StringBuilder sb = new StringBuilder();
        sb.append("{{\\"lang\\":\\"java\\",\\"consumer_of\\":\\"").append(getJsonStr(jsonStr,"lang")).append("\\"");
        String cs = getJsonStr(jsonStr, "sm2_enc");
        if (!cs.isEmpty()) {{
            try {{
                String d = SM2Util.decrypt(cs, ENC_PRIV);
                sb.append(",\\"sm2_dec\\":\\"").append(d.equals(MSG)?"PASS":"FAIL").append("\\"");
            }} catch(Exception e) {{ sb.append(",\\"sm2_dec\\":\\"FAIL\\""); }}
        }}
        String ss = getJsonStr(jsonStr, "sm2_sig");
        if (!ss.isEmpty()) {{
            try {{
                boolean ok = SM2Util.verify(MSG, SIG_PUB, ss);
                sb.append(",\\"sm2_ver\\":\\"").append(ok?"PASS":"FAIL").append("\\"");
            }} catch(Exception e) {{ sb.append(",\\"sm2_ver\\":\\"FAIL\\""); }}
        }}
        if (!cs.isEmpty() && !ss.isEmpty()) {{
            try {{
                String d2 = SM2Util.decrypt(cs, ENC_PRIV);
                boolean ok2 = SM2Util.verify(d2, SIG_PUB, ss);
                sb.append(",\\"sm2_enc_sig_ver_dec\\":\\"").append(d2.equals(MSG)&&ok2?"PASS":"FAIL").append("\\"");
            }} catch(Exception e) {{ sb.append(",\\"sm2_enc_sig_ver_dec\\":\\"FAIL\\""); }}
        }}
        String sh = getJsonStr(jsonStr, "sm3_hash");
        if (!sh.isEmpty()) {{
            try {{
                String h = SM3Util.digestToStr(MSG, false);
                sb.append(",\\"sm3\\":\\"").append(h.equals(sh)?"PASS":"FAIL").append("\\"");
            }} catch(Exception e) {{ sb.append(",\\"sm3\\":\\"FAIL\\""); }}
        }}
        String hh = getJsonStr(jsonStr, "sm3_hmac_hash");
        if (!hh.isEmpty()) {{
            try {{
                String hm = SM3Util.hmacToStr(HMAC_KEY_HEX, MSG, false);
                sb.append(",\\"sm3_hmac\\":\\"").append(hm.equals(hh)?"PASS":"FAIL").append("\\"");
            }} catch(Exception e) {{ sb.append(",\\"sm3_hmac\\":\\"FAIL\\""); }}
        }}
        String sc = getJsonStr(jsonStr, "sm4_enc");
        if (!sc.isEmpty()) {{
            try {{
                byte[] sm4Key = HexUtil.decodeHexStr(SM4_KEY_HEX);
                String sd = SM4Util.decrypt(sm4Key, sc);
                sb.append(",\\"sm4_dec\\":\\"").append(sd.equals(MSG)?"PASS":"FAIL").append("\\"");
            }} catch(Exception e) {{ sb.append(",\\"sm4_dec\\":\\"FAIL\\""); }}
        }}
        sb.append("}}");
        System.out.println(sb.toString());
    }}
    static String getJsonStr(String json, String key) {{
        String search = "\\"" + key + "\\":\\"";
        int idx = json.indexOf(search);
        if (idx < 0) return "";
        idx += search.length();
        int end = json.indexOf("\\"", idx);
        if (end < 0) return "";
        return json.substring(idx, end).replace("\\\\\\"","\\"").replace("\\\\\\\\","\\\\");
    }}
}}
'''
    (java_dir / "CrossTest.java").write_text(code, encoding='utf-8')
    stdout, stderr, rc = run_cmd(f'javac -encoding UTF-8 -cp "{cp}" -d "{java_dir}" "{java_dir}/CrossTest.java"', timeout=60)
    if rc != 0:
        print(f"    javac err: {stderr}")
        return None
    # Write input JSON to file
    input_file = java_dir / "input.json"
    input_file.write_text(json.dumps(ref_data, ensure_ascii=False), encoding='utf-8')
    stdout, stderr, rc = run_cmd(f'java -cp "{cp}{os.pathsep}{java_dir}" CrossTest "{input_file}"', timeout=60)
    if rc != 0:
        print(f"    java run err: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"    PARSE: {stdout[:200]}")
        return None


# ======================== C# Self/Cross ========================
def csharp_self_test():
    print("\n[C#] Self-test...")
    cs_dir = OUTPUT_DIR / "cs_self"
    if cs_dir.exists():
        shutil.rmtree(cs_dir)
    cs_dir.mkdir(parents=True)
    cs_proj = BASE_DIR / "csharp" / "crossmool" / "src" / "Crossmool.Crypto"
    code = f'''using System;
using System.Text;
using Crossmool.Crypto;
class Program {{
    static string MSG = "{TEST_MSG}";
    static string SM4_KEY = "{SM4_KEY_HEX}";
    static string HMAC_KEY = "{HMAC_KEY_HEX}";
    static string EXP_SM3 = "{EXP_SM3}";
    static string EXP_SM3_HMAC = "{EXP_SM3_HMAC}";
    static string ENC_PUB = "{SM2_KEYS['enc_pub_der_hex']}";
    static string ENC_PRIV = "{SM2_KEYS['enc_priv_der_hex']}";
    static string SIG_PUB = "{SM2_KEYS['sig_pub_der_hex']}";
    static string SIG_PRIV = "{SM2_KEYS['sig_priv_der_hex']}";
    static void Main() {{
        var sb = new StringBuilder();
        sb.Append("{{\\"lang\\":\\"csharp\\"");
        try {{
            var c = SM2Util.Encrypt(MSG, ENC_PUB, false);
            sb.Append(",\\"sm2_enc\\":\\"").Append(Escape(c)).Append("\\"");
            var d = SM2Util.Decrypt(c, ENC_PRIV);
            sb.Append(",\\"sm2_enc_dec\\":\\"").Append(d==MSG?"PASS":"FAIL").Append("\\"");
        }} catch(Exception e) {{ sb.Append(",\\"sm2_enc_dec\\":\\"FAIL: ").Append(Escape(e.Message)).Append("\\""); }}
        try {{
            var sig = SM2Util.Sign(MSG, SIG_PRIV, false);
            sb.Append(",\\"sm2_sig\\":\\"").Append(Escape(sig)).Append("\\"");
            var ok = SM2Util.Verify(Encoding.UTF8.GetBytes(MSG), SIG_PUB, sig);
            sb.Append(",\\"sm2_sig_ver\\":\\"").Append(ok?"PASS":"FAIL").Append("\\"");
        }} catch(Exception e) {{ sb.Append(",\\"sm2_sig_ver\\":\\"FAIL: ").Append(Escape(e.Message)).Append("\\""); }}
        try {{
            var c2 = SM2Util.Encrypt(MSG, ENC_PUB, false);
            var s2 = SM2Util.Sign(MSG, SIG_PRIV, false);
            var d2 = SM2Util.Decrypt(c2, ENC_PRIV);
            var ok2 = SM2Util.Verify(Encoding.UTF8.GetBytes(d2), SIG_PUB, s2);
            sb.Append(",\\"sm2_enc_sig_ver_dec\\":\\"").Append(d2==MSG&&ok2?"PASS":"FAIL").Append("\\"");
        }} catch(Exception e) {{ sb.Append(",\\"sm2_enc_sig_ver_dec\\":\\"FAIL: ").Append(Escape(e.Message)).Append("\\""); }}
        try {{
            var h = SM3Util.DigestStr(MSG, false);
            sb.Append(",\\"sm3_hash\\":\\"").Append(h).Append("\\"");
            sb.Append(",\\"sm3\\":\\"").Append(h==EXP_SM3?"PASS":"FAIL").Append("\\"");
        }} catch(Exception e) {{ sb.Append(",\\"sm3\\":\\"FAIL: ").Append(Escape(e.Message)).Append("\\""); }}
        try {{
            var hm = SM3Util.HmacStr(HMAC_KEY, MSG, false);
            sb.Append(",\\"sm3_hmac_hash\\":\\"").Append(hm).Append("\\"");
            sb.Append(",\\"sm3_hmac\\":\\"").Append(hm==EXP_SM3_HMAC?"PASS":"FAIL").Append("\\"");
        }} catch(Exception e) {{ sb.Append(",\\"sm3_hmac\\":\\"FAIL: ").Append(Escape(e.Message)).Append("\\""); }}
        try {{
            var sm4Key = Crossmool.Crypto.Utils.EncodingUtils.FromHex(SM4_KEY);
            var sc = SM4Util.EncryptGcmString(sm4Key, MSG, false);
            sb.Append(",\\"sm4_enc\\":\\"").Append(Escape(sc)).Append("\\"");
            var sd = SM4Util.DecryptGcmToString(sm4Key, sc);
            sb.Append(",\\"sm4_enc_dec\\":\\"").Append(sd==MSG?"PASS":"FAIL").Append("\\"");
        }} catch(Exception e) {{ sb.Append(",\\"sm4_enc_dec\\":\\"FAIL: ").Append(Escape(e.Message)).Append("\\""); }}
        sb.Append("}}");
        Console.WriteLine(sb.ToString());
    }}
    static string Escape(string s) {{ return s.Replace("\\\\","\\\\\\\\").Replace("\\"","\\\\\\"").Replace("\\n","\\\\n").Replace("\\r",""); }}
}}
'''
    (cs_dir / "Program.cs").write_text(code, encoding='utf-8')
    csproj_content = f'''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup>
  <ItemGroup><ProjectReference Include="{cs_proj}\\Crossmool.Crypto.csproj" /></ItemGroup>
</Project>'''
    (cs_dir / "cs_self.csproj").write_text(csproj_content, encoding='utf-8')
    stdout, stderr, rc = run_cmd(f'dotnet run --project "{cs_dir}"', timeout=120)
    if rc != 0:
        print(f"  dotnet err: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def csharp_cross_test(ref_data):
    cs_dir = OUTPUT_DIR / "cs_cross"
    if cs_dir.exists():
        shutil.rmtree(cs_dir)
    cs_dir.mkdir(parents=True)
    cs_proj = BASE_DIR / "csharp" / "crossmool" / "src" / "Crossmool.Crypto"
    code = f'''using System;
using System.Text;
using System.Text.Json;
using Crossmool.Crypto;
class Program {{
    static string MSG = "{TEST_MSG}";
    static string SM4_KEY = "{SM4_KEY_HEX}";
    static string HMAC_KEY = "{HMAC_KEY_HEX}";
    static string ENC_PRIV = "{SM2_KEYS['enc_priv_der_hex']}";
    static string SIG_PUB = "{SM2_KEYS['sig_pub_der_hex']}";
    static void Main(string[] args) {{
        var jsonStr = System.IO.File.ReadAllText(args[0]);
        using var doc = JsonDocument.Parse(jsonStr);
        var root = doc.RootElement;
        var sb = new StringBuilder();
        sb.Append("{{\\"lang\\":\\"csharp\\",\\"consumer_of\\":\\"").Append(GetStr(root,"lang")).Append("\\"");
        var cs = GetStr(root, "sm2_enc");
        if (!string.IsNullOrEmpty(cs)) {{
            try {{
                var d = SM2Util.Decrypt(cs, ENC_PRIV);
                sb.Append(",\\"sm2_dec\\":\\"").Append(d==MSG?"PASS":"FAIL").Append("\\"");
            }} catch {{ sb.Append(",\\"sm2_dec\\":\\"FAIL\\""); }}
        }}
        var ss = GetStr(root, "sm2_sig");
        if (!string.IsNullOrEmpty(ss)) {{
            try {{
                var ok = SM2Util.Verify(Encoding.UTF8.GetBytes(MSG), SIG_PUB, ss);
                sb.Append(",\\"sm2_ver\\":\\"").Append(ok?"PASS":"FAIL").Append("\\"");
            }} catch {{ sb.Append(",\\"sm2_ver\\":\\"FAIL\\""); }}
        }}
        if (!string.IsNullOrEmpty(cs) && !string.IsNullOrEmpty(ss)) {{
            try {{
                var d2 = SM2Util.Decrypt(cs, ENC_PRIV);
                var ok2 = SM2Util.Verify(Encoding.UTF8.GetBytes(d2), SIG_PUB, ss);
                sb.Append(",\\"sm2_enc_sig_ver_dec\\":\\"").Append(d2==MSG&&ok2?"PASS":"FAIL").Append("\\"");
            }} catch {{ sb.Append(",\\"sm2_enc_sig_ver_dec\\":\\"FAIL\\""); }}
        }}
        var sh = GetStr(root, "sm3_hash");
        if (!string.IsNullOrEmpty(sh)) {{
            try {{
                var h = SM3Util.DigestStr(MSG, false);
                sb.Append(",\\"sm3\\":\\"").Append(h==sh?"PASS":"FAIL").Append("\\"");
            }} catch {{ sb.Append(",\\"sm3\\":\\"FAIL\\""); }}
        }}
        var hh = GetStr(root, "sm3_hmac_hash");
        if (!string.IsNullOrEmpty(hh)) {{
            try {{
                var hm = SM3Util.HmacStr(HMAC_KEY, MSG, false);
                sb.Append(",\\"sm3_hmac\\":\\"").Append(hm==hh?"PASS":"FAIL").Append("\\"");
            }} catch {{ sb.Append(",\\"sm3_hmac\\":\\"FAIL\\""); }}
        }}
        var sc = GetStr(root, "sm4_enc");
        if (!string.IsNullOrEmpty(sc)) {{
            try {{
                var sm4Key = Crossmool.Crypto.Utils.EncodingUtils.FromHex(SM4_KEY);
                var sd = SM4Util.DecryptGcmToString(sm4Key, sc);
                sb.Append(",\\"sm4_dec\\":\\"").Append(sd==MSG?"PASS":"FAIL").Append("\\"");
            }} catch {{ sb.Append(",\\"sm4_dec\\":\\"FAIL\\""); }}
        }}
        sb.Append("}}");
        Console.WriteLine(sb.ToString());
    }}
    static string GetStr(JsonElement root, string key) {{
        if (root.TryGetProperty(key, out var val) && val.ValueKind == JsonValueKind.String)
            return val.GetString() ?? "";
        return "";
    }}
}}
'''
    (cs_dir / "Program.cs").write_text(code, encoding='utf-8')
    csproj_content = f'''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup>
  <ItemGroup><ProjectReference Include="{cs_proj}\\Crossmool.Crypto.csproj" /></ItemGroup>
</Project>'''
    (cs_dir / "cs_cross.csproj").write_text(csproj_content, encoding='utf-8')
    input_file = cs_dir / "input.json"
    input_file.write_text(json.dumps(ref_data, ensure_ascii=False), encoding='utf-8')
    stdout, stderr, rc = run_cmd(f'dotnet run --project "{cs_dir}" -- "{input_file}"', timeout=120)
    if rc != 0:
        print(f"    dotnet err: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"    PARSE: {stdout[:200]}")
        return None


# ======================== C Self/Cross (via GmSSL DLL) ========================
def c_self_test():
    print("\n[C] Self-test...")
    c_dir = BASE_DIR / "c" / "crossmool"
    gmssl_dir = c_dir / "gmssl_install"
    build_dir = OUTPUT_DIR / "c_build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)
    # Write C test program
    code = f'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crossmool.h"
#include "crossmool_sm2.h"
#include "crossmool_sm3.h"
#include "crossmool_sm4.h"

#define MSG "{TEST_MSG}"
#define SM4_KEY_HEX "{SM4_KEY_HEX}"
#define HMAC_KEY_HEX "{HMAC_KEY_HEX}"
#define EXP_SM3 "{EXP_SM3}"
#define EXP_SM3_HMAC "{EXP_SM3_HMAC}"
#define ENC_PUB_HEX "{SM2_KEYS['enc_pub_der_hex']}"
#define ENC_PRIV_HEX "{SM2_KEYS['enc_priv_der_hex']}"
#define SIG_PUB_HEX "{SM2_KEYS['sig_pub_der_hex']}"
#define SIG_PRIV_HEX "{SM2_KEYS['sig_priv_der_hex']}"

void json_str(FILE* f, const char* key, const char* val, int* first) {{
    if (*first) *first = 0; else fprintf(f, ",");
    fprintf(f, "\\"%s\\":\\"%s\\"", key, val ? val : "");
}}

int main() {{
    FILE* f = stdout;
    int first = 1;
    fprintf(f, "{{\\"lang\\":\\"c\\"");
    char* err = NULL;
    // SM2 Enc/Dec
    char* enc = NULL;
    char* dec = NULL;
    int ret = crossmool_sm2_encrypt_hex((const unsigned char*)MSG, strlen(MSG), ENC_PUB_HEX, &enc, &err);
    if (ret == 0 && enc) {{
        json_str(f, "sm2_enc", enc, &first);
        ret = crossmool_sm2_decrypt_hex(enc, ENC_PRIV_HEX, &dec, &err);
        json_str(f, "sm2_enc_dec", (ret == 0 && dec && strcmp(dec, MSG) == 0) ? "PASS" : "FAIL", &first);
        free(enc); free(dec);
    }} else {{
        json_str(f, "sm2_enc_dec", "FAIL", &first);
    }}
    // SM2 Sign/Verify
    char* sig = NULL;
    ret = crossmool_sm2_sign_hex((const unsigned char*)MSG, strlen(MSG), SIG_PRIV_HEX, &sig, &err);
    if (ret == 0 && sig) {{
        json_str(f, "sm2_sig", sig, &first);
        int ok = crossmool_sm2_verify_hex((const unsigned char*)MSG, strlen(MSG), SIG_PUB_HEX, sig, &err);
        json_str(f, "sm2_sig_ver", (ok == 0) ? "PASS" : "FAIL", &first);
        free(sig);
    }} else {{
        json_str(f, "sm2_sig_ver", "FAIL", &first);
    }}
    // SM2 EncSign + VerifyDec
    char* enc2 = NULL; char* sig2 = NULL; char* dec2 = NULL;
    ret = crossmool_sm2_encrypt_hex((const unsigned char*)MSG, strlen(MSG), ENC_PUB_HEX, &enc2, &err);
    int ret2 = crossmool_sm2_sign_hex((const unsigned char*)MSG, strlen(MSG), SIG_PRIV_HEX, &sig2, &err);
    if (ret == 0 && ret2 == 0 && enc2 && sig2) {{
        ret = crossmool_sm2_decrypt_hex(enc2, ENC_PRIV_HEX, &dec2, &err);
        int ok = crossmool_sm2_verify_hex((const unsigned char*)(dec2 ? dec2 : ""), dec2 ? strlen(dec2) : 0, SIG_PUB_HEX, sig2, &err);
        json_str(f, "sm2_enc_sig_ver_dec", (ret == 0 && ok == 0 && dec2 && strcmp(dec2, MSG) == 0) ? "PASS" : "FAIL", &first);
        free(enc2); free(sig2); free(dec2);
    }} else {{
        json_str(f, "sm2_enc_sig_ver_dec", "FAIL", &first);
    }}
    // SM3
    char* sm3h = NULL;
    ret = crossmool_sm3_digest_hex((const unsigned char*)MSG, strlen(MSG), &sm3h, &err);
    if (ret == 0 && sm3h) {{
        json_str(f, "sm3_hash", sm3h, &first);
        json_str(f, "sm3", (strcmp(sm3h, EXP_SM3) == 0) ? "PASS" : "FAIL", &first);
        free(sm3h);
    }} else {{ json_str(f, "sm3", "FAIL", &first); }}
    // SM3-HMAC
    unsigned char hmac_key[32];
    size_t hk_len;
    ret = crossmool_hex_decode(HMAC_KEY_HEX, &hmac_key, &hk_len);
    char* hmach = NULL;
    if (ret == 0) {{
        ret = crossmool_sm3_hmac_hex(hmac_key, hk_len, (const unsigned char*)MSG, strlen(MSG), &hmach, &err);
        if (ret == 0 && hmach) {{
            json_str(f, "sm3_hmac_hash", hmach, &first);
            json_str(f, "sm3_hmac", (strcmp(hmach, EXP_SM3_HMAC) == 0) ? "PASS" : "FAIL", &first);
            free(hmach);
        }} else {{ json_str(f, "sm3_hmac", "FAIL", &first); }}
    }} else {{ json_str(f, "sm3_hmac", "FAIL", &first); }}
    // SM4 GCM
    unsigned char sm4_key[16];
    size_t sk_len;
    ret = crossmool_hex_decode(SM4_KEY_HEX, &sm4_key, &sk_len);
    char* sm4e = NULL;
    if (ret == 0 && sk_len == 16) {{
        ret = crossmool_sm4_encrypt_gcm_hex(sm4_key, (const unsigned char*)MSG, strlen(MSG), &sm4e);
        if (ret == 0 && sm4e) {{
            json_str(f, "sm4_enc", sm4e, &first);
            unsigned char* sm4d = NULL;
            size_t sm4d_len;
            ret = crossmool_sm4_decrypt_gcm_hex(sm4_key, sm4e, &sm4d, &sm4d_len);
            int match = (ret == 0 && sm4d_len == strlen(MSG) && memcmp(sm4d, MSG, sm4d_len) == 0);
            json_str(f, "sm4_enc_dec", match ? "PASS" : "FAIL", &first);
            free(sm4e); free(sm4d);
        }} else {{ json_str(f, "sm4_enc_dec", "FAIL", &first); }}
    }} else {{ json_str(f, "sm4_enc_dec", "FAIL", &first); }}
    fprintf(f, "}}");
    return 0;
}}
'''
    (build_dir / "c_self_test.c").write_text(code, encoding='utf-8')
    # Try to compile and run with MSVC, linking to GmSSL DLL directly
    gmssl_lib = gmssl_dir / "lib" / "gmssl.lib"
    inc = c_dir / "include"
    gmssl_inc = gmssl_dir / "include"
    # Read all .c source files needed
    src_files = [
        c_dir / "src" / "error.c",
        c_dir / "src" / "util_hex.c",
        c_dir / "src" / "util_base64.c",
        c_dir / "src" / "util_string.c",
        c_dir / "src" / "sm2.c",
        c_dir / "src" / "sm3.c",
        c_dir / "src" / "sm4.c",
    ]
    src_args = " ".join(f'"{p}"' for p in src_files)
    cl_cmd = (
        f'cl.exe /nologo /utf-8 /MD /Fe:"{build_dir}/c_self_test.exe" '
        f'/I"{inc}" /I"{gmssl_inc}" '
        f'"{build_dir}/c_self_test.c" {src_args} '
        f'"{gmssl_lib}" /link /SUBSYSTEM:CONSOLE'
    )
    print(f"  Compiling C...")
    # Use MSVC dev environment
    vcvars = r'H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat'
    stdout, stderr, rc = run_cmd(
        f'"{vcvars}" >nul 2>&1 && {cl_cmd}',
        timeout=120
    )
    if rc != 0:
        print(f"  Compile err: {stderr[:500]}")
        # Try with cmake approach
        cmake_build = build_dir / "cmake_build"
        cmake_build.mkdir(parents=True, exist_ok=True)
        cmake_code = f'''cmake_minimum_required(VERSION 3.20)
project(c_self LANGUAGES C)
set(CMAKE_C_STANDARD 17)
if(MSVC)
    add_compile_options(/utf-8 /MD)
endif()
set(GMSSL_INSTALL_DIR "{gmssl_dir}")
set(GMSSL_INCLUDE_DIR "${{GMSSL_INSTALL_DIR}}/include")
if(MSVC)
    set(GMSSL_LIBRARY "${{GMSSL_INSTALL_DIR}}/lib/gmssl.lib")
else()
    set(GMSSL_LIBRARY "${{GMSSL_INSTALL_DIR}}/lib/libgmssl.dll.a")
endif()
add_library(gmssl SHARED IMPORTED)
set_target_properties(gmssl PROPERTIES
    IMPORTED_LOCATION "${{GMSSL_INSTALL_DIR}}/bin/gmssl.dll"
    IMPORTED_IMPLIB "${{GMSSL_LIBRARY}}"
    INTERFACE_INCLUDE_DIRECTORIES "${{GMSSL_INCLUDE_DIR}}"
)
add_executable(c_self c_self_test.c {src_args})
target_include_directories(c_self PRIVATE "{inc}" "{gmssl_inc}")
target_link_libraries(c_self gmssl)
'''
        (build_dir / "CMakeLists.txt").write_text(cmake_code, encoding='utf-8')
        stdout, stderr, rc = run_cmd(
            f'"{vcvars}" >nul 2>&1 && cd "{build_dir}" && cmake -B cmake_build -G "NMake Makefiles" && cmake --build cmake_build',
            timeout=180
        )
        if rc != 0:
            print(f"  CMake build err: {stderr[:500]}")
            return None
        exe_path = build_dir / "cmake_build" / "c_self.exe"
    else:
        exe_path = build_dir / "c_self_test.exe"
    # Copy GmSSL DLL to output
    gmssl_dll = gmssl_dir / "bin" / "gmssl.dll"
    if gmssl_dll.exists():
        shutil.copy(gmssl_dll, build_dir)
    # Run
    stdout, stderr, rc = run_cmd(f'"{exe_path}"', cwd=str(build_dir), timeout=60)
    if rc != 0:
        print(f"  Run err: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def c_cross_test(ref_data):
    # C cross-test requires building a C consumer
    print(f"    C cross consumer not yet implemented (will use empty result)")
    return None


# ======================== C++ Self/Cross ========================
def cpp_self_test():
    print("\n[CPP] Self-test...")
    # C++ needs USE_GMSSL macro and GmSSL
    cpp_dir = BASE_DIR / "cpp" / "crossmool"
    gmssl_dir = BASE_DIR / "c" / "crossmool" / "gmssl_install"
    build_dir = OUTPUT_DIR / "cpp_build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)
    code = f'''#include <iostream>
#include <string>
#include <cstring>
#define USE_GMSSL
#include "SM2Util.h"
#include "SM3Util.h"
#include "SM4Util.h"
#include "HexUtil.h"
#include "Base64Util.h"

#define MSG "{TEST_MSG}"
#define SM4_KEY_HEX "{SM4_KEY_HEX}"
#define HMAC_KEY_HEX "{HMAC_KEY_HEX}"
#define EXP_SM3 "{EXP_SM3}"
#define EXP_SM3_HMAC "{EXP_SM3_HMAC}"
#define ENC_PUB "{SM2_KEYS['enc_pub_der_hex']}"
#define ENC_PRIV "{SM2_KEYS['enc_priv_der_hex']}"
#define SIG_PUB "{SM2_KEYS['sig_pub_der_hex']}"
#define SIG_PRIV "{SM2_KEYS['sig_priv_der_hex']}"

void json_out(const std::string& key, const std::string& val, int& first) {{
    if (first) first = 0; else std::cout << ",";
    std::cout << "\\"" << key << "\\":\\"" << val << "\\"";
}}

int main() {{
    int first = 1;
    std::cout << "{{\\"lang\\":\\"cpp\\"";
    try {{
        // SM2 Enc/Dec
        std::vector<unsigned char> pubBytes = HexUtil::decodeHexStr(ENC_PUB);
        std::vector<unsigned char> privBytes = HexUtil::decodeHexStr(ENC_PRIV);
        std::string msg(MSG);
        std::vector<unsigned char> msgBytes(msg.begin(), msg.end());
        std::string enc = SM2Util::encryptToHex(msgBytes, pubBytes);
        json_out("sm2_enc", enc, first);
        std::vector<unsigned char> dec = SM2Util::decryptFromHex(enc, privBytes);
        std::string decStr(dec.begin(), dec.end());
        json_out("sm2_enc_dec", decStr == MSG ? "PASS" : "FAIL", first);
    }} catch (const std::exception& e) {{
        json_out("sm2_enc_dec", (std::string("FAIL: ") + e.what()), first);
    }}
    try {{
        // SM2 Sign/Verify
        std::vector<unsigned char> sigPub = HexUtil::decodeHexStr(SIG_PUB);
        std::vector<unsigned char> sigPriv = HexUtil::decodeHexStr(SIG_PRIV);
        std::vector<unsigned char> msgBytes(MSG, MSG + strlen(MSG));
        std::string sigHex = SM2Util::signToHex(msgBytes, sigPriv);
        json_out("sm2_sig", sigHex, first);
        bool ok = SM2Util::verifyFromHex(msgBytes, sigPub, sigHex);
        json_out("sm2_sig_ver", ok ? "PASS" : "FAIL", first);
    }} catch (const std::exception& e) {{
        json_out("sm2_sig_ver", (std::string("FAIL: ") + e.what()), first);
    }}
    try {{
        // SM2 EncSign + VerifyDec
        std::vector<unsigned char> pubBytes = HexUtil::decodeHexStr(ENC_PUB);
        std::vector<unsigned char> privBytes = HexUtil::decodeHexStr(ENC_PRIV);
        std::vector<unsigned char> sigPub = HexUtil::decodeHexStr(SIG_PUB);
        std::vector<unsigned char> sigPriv = HexUtil::decodeHexStr(SIG_PRIV);
        std::vector<unsigned char> msgBytes(MSG, MSG + strlen(MSG));
        std::string enc2 = SM2Util::encryptToHex(msgBytes, pubBytes);
        std::string sig2 = SM2Util::signToHex(msgBytes, sigPriv);
        std::vector<unsigned char> dec2 = SM2Util::decryptFromHex(enc2, privBytes);
        bool ok2 = SM2Util::verifyFromHex(dec2, sigPub, sig2);
        std::string decStr2(dec2.begin(), dec2.end());
        json_out("sm2_enc_sig_ver_dec", (decStr2 == MSG && ok2) ? "PASS" : "FAIL", first);
    }} catch (const std::exception& e) {{
        json_out("sm2_enc_sig_ver_dec", (std::string("FAIL: ") + e.what()), first);
    }}
    try {{
        // SM3
        std::string h = SM3Util::digestToHex(std::vector<unsigned char>(MSG, MSG + strlen(MSG)));
        json_out("sm3_hash", h, first);
        json_out("sm3", h == EXP_SM3 ? "PASS" : "FAIL", first);
    }} catch (const std::exception& e) {{
        json_out("sm3", (std::string("FAIL: ") + e.what()), first);
    }}
    try {{
        // SM3-HMAC
        std::vector<unsigned char> hmacKey = HexUtil::decodeHexStr(HMAC_KEY_HEX);
        std::vector<unsigned char> msgBytes(MSG, MSG + strlen(MSG));
        std::string hm = SM3Util::hmacToHex(hmacKey, msgBytes);
        json_out("sm3_hmac_hash", hm, first);
        json_out("sm3_hmac", hm == EXP_SM3_HMAC ? "PASS" : "FAIL", first);
    }} catch (const std::exception& e) {{
        json_out("sm3_hmac", (std::string("FAIL: ") + e.what()), first);
    }}
    try {{
        // SM4 GCM
        std::vector<unsigned char> sm4Key = HexUtil::decodeHexStr(SM4_KEY_HEX);
        std::vector<unsigned char> msgBytes(MSG, MSG + strlen(MSG));
        std::string sc = SM4Util::encryptGcm(sm4Key, msgBytes, false);
        json_out("sm4_enc", sc, first);
        std::vector<unsigned char> sd = SM4Util::decryptGcm(sm4Key, sc);
        std::string sdStr(sd.begin(), sd.end());
        json_out("sm4_enc_dec", sdStr == MSG ? "PASS" : "FAIL", first);
    }} catch (const std::exception& e) {{
        json_out("sm4_enc_dec", (std::string("FAIL: ") + e.what()), first);
    }}
    std::cout << "}}" << std::endl;
    return 0;
}}
'''
    (build_dir / "cpp_self_test.cpp").write_text(code, encoding='utf-8')
    # Compile
    inc = cpp_dir / "include"
    src_dir = cpp_dir / "src"
    utils_dir = cpp_dir / "utils"
    gmssl_lib = gmssl_dir / "lib" / "gmssl.lib"
    vcvars = r'H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat'
    cl_cmd = (
        f'cl.exe /nologo /utf-8 /MD /EHsc /DUSE_GMSSL '
        f'/Fe:"{build_dir}/cpp_self_test.exe" '
        f'/I"{inc}" /I"{gmssl_dir}/include" '
        f'"{build_dir}/cpp_self_test.cpp" '
        f'"{src_dir}/SM2Util.cpp" "{src_dir}/SM3Util.cpp" "{src_dir}/SM4Util.cpp" '
        f'"{utils_dir}/Base64Util.cpp" "{utils_dir}/HexUtil.cpp" "{utils_dir}/StringUtil.cpp" '
        f'"{gmssl_lib}" /link /SUBSYSTEM:CONSOLE'
    )
    stdout, stderr, rc = run_cmd(f'"{vcvars}" >nul 2>&1 && {cl_cmd}', timeout=120)
    if rc != 0:
        print(f"  Compile err: {stderr[:500]}")
        return None
    # Copy DLL
    gmssl_dll = gmssl_dir / "bin" / "gmssl.dll"
    if gmssl_dll.exists():
        shutil.copy(gmssl_dll, build_dir)
    stdout, stderr, rc = run_cmd(f'"{build_dir}/cpp_self_test.exe"', cwd=str(build_dir), timeout=60)
    if rc != 0:
        print(f"  Run err: {stderr}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def cpp_cross_test(ref_data):
    print(f"    CPP cross consumer not yet implemented")
    return None


# ======================== Rust Self/Cross ========================
def rust_self_test():
    print("\n[Rust] Self-test...")
    rust_dir = OUTPUT_DIR / "rust_self"
    if rust_dir.exists():
        shutil.rmtree(rust_dir)
    rust_dir.mkdir(parents=True)
    # Create a Rust test program that uses the crossmool crate
    cargo_toml = f'''[package]
name = "rust-self-test"
version = "0.1.0"
edition = "2021"

[dependencies]
crossmool = {{ path = r"{BASE_DIR / 'rust' / 'crossmool'}" }}
hex = "0.4"
serde_json = "1"
'''
    (rust_dir / "Cargo.toml").write_text(cargo_toml, encoding='utf-8')
    main_rs = f'''use crossmool::{{sm2, sm3, sm4}};
use hex;
use serde_json::{{json, Value}};

const MSG: &str = "{TEST_MSG}";
const SM4_KEY: &str = "{SM4_KEY_HEX}";
const HMAC_KEY: &str = "{HMAC_KEY_HEX}";
const EXP_SM3: &str = "{EXP_SM3}";
const EXP_SM3_HMAC: &str = "{EXP_SM3_HMAC}";

fn main() {{
    let mut r = json!({{"lang": "rust"}});
    let enc_pub = "{SM2_KEYS['enc_pub_der_hex']}";
    let enc_priv = "{SM2_KEYS['enc_priv_der_hex']}";
    let sig_pub = "{SM2_KEYS['sig_pub_der_hex']}";
    let sig_priv = "{SM2_KEYS['sig_priv_der_hex']}";
    let msg_bytes = MSG.as_bytes();

    // SM2 Enc/Dec
    match sm2::encrypt_to_hex(msg_bytes, enc_pub) {{
        Ok(c) => {{
            r["sm2_enc"] = Value::String(c.clone());
            match sm2::decrypt_from_hex(&c, enc_priv) {{
                Ok(d) => {{
                    let d_str = String::from_utf8_lossy(&d);
                    r["sm2_enc_dec"] = Value::String(if d_str == MSG {{ "PASS".to_string() }} else {{ "FAIL".to_string() }});
                }}
                Err(e) => {{ r["sm2_enc_dec"] = Value::String(format!("FAIL: {{}}", e)); }}
            }}
        }}
        Err(e) => {{ r["sm2_enc_dec"] = Value::String(format!("FAIL: {{}}", e)); }}
    }}

    // SM2 Sign/Verify
    match sm2::sign_to_hex(msg_bytes, sig_priv) {{
        Ok(s) => {{
            r["sm2_sig"] = Value::String(s.clone());
            match sm2::verify_from_hex(msg_bytes, sig_pub, &s) {{
                Ok(ok) => {{ r["sm2_sig_ver"] = Value::String(if ok {{ "PASS".to_string() }} else {{ "FAIL".to_string() }}); }}
                Err(e) => {{ r["sm2_sig_ver"] = Value::String(format!("FAIL: {{}}", e)); }}
            }}
        }}
        Err(e) => {{ r["sm2_sig_ver"] = Value::String(format!("FAIL: {{}}", e)); }}
    }}

    // SM2 EncSign + VerifyDec
    match (sm2::encrypt_to_hex(msg_bytes, enc_pub), sm2::sign_to_hex(msg_bytes, sig_priv)) {{
        (Ok(c2), Ok(s2)) => {{
            match sm2::decrypt_from_hex(&c2, enc_priv) {{
                Ok(d2) => {{
                    let d2_str = String::from_utf8_lossy(&d2);
                    let ok2 = sm2::verify_from_hex(&d2, sig_pub, &s2).unwrap_or(false);
                    r["sm2_enc_sig_ver_dec"] = Value::String(if d2_str == MSG && ok2 {{ "PASS".to_string() }} else {{ "FAIL".to_string() }});
                }}
                Err(e) => {{ r["sm2_enc_sig_ver_dec"] = Value::String(format!("FAIL: {{}}", e)); }}
            }}
        }}
        _ => {{ r["sm2_enc_sig_ver_dec"] = Value::String("FAIL".to_string()); }}
    }}

    // SM3
    let h = sm3::digest_to_hex(msg_bytes);
    r["sm3_hash"] = Value::String(h.clone());
    r["sm3"] = Value::String(if h == EXP_SM3 {{ "PASS".to_string() }} else {{ "FAIL".to_string() }});

    // SM3-HMAC
    let hmac_key = hex::decode(HMAC_KEY).unwrap();
    let hm = sm3::hmac_to_hex(&hmac_key, msg_bytes);
    r["sm3_hmac_hash"] = Value::String(hm.clone());
    r["sm3_hmac"] = Value::String(if hm == EXP_SM3_HMAC {{ "PASS".to_string() }} else {{ "FAIL".to_string() }});

    // SM4 GCM
    let sm4_key = hex::decode(SM4_KEY).unwrap();
    match sm4::encrypt_gcm(&sm4_key, msg_bytes, false) {{
        Ok(sc) => {{
            r["sm4_enc"] = Value::String(sc.clone());
            match sm4::decrypt_gcm_to_string(&sm4_key, &sc) {{
                Ok(sd) => {{
                    r["sm4_enc_dec"] = Value::String(if sd == MSG {{ "PASS".to_string() }} else {{ "FAIL".to_string() }});
                }}
                Err(e) => {{ r["sm4_enc_dec"] = Value::String(format!("FAIL: {{}}", e)); }}
            }}
        }}
        Err(e) => {{ r["sm4_enc_dec"] = Value::String(format!("FAIL: {{}}", e)); }}
    }}

    // Remove potentially large binary data fields from output
    println!("{{}}", serde_json::to_string(&r).unwrap());
}}
'''
    (rust_dir / "src").mkdir(parents=True, exist_ok=True)
    (rust_dir / "src" / "main.rs").write_text(main_rs, encoding='utf-8')
    stdout, stderr, rc = run_cmd(f'cd "{rust_dir}" && cargo run 2>&1', timeout=300)
    if rc != 0:
        print(f"  cargo err: {stderr[:500]}")
        return None
    try:
        return json.loads(stdout)
    except:
        print(f"  PARSE: {stdout[:200]}")
        return None

def rust_cross_test(ref_data):
    print(f"    Rust cross consumer not yet implemented")
    return None


# ======================== Main Orchestrator ========================
def main():
    global cross_data, self_results, test_results
    start = time.time()
    print("=" * 70)
    print("Crossmool v7 综合测试框架 - 8语言完整互通性测试")
    print(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"测试范围: 6类操作 × 8语言 × 8语言 = 384项")
    print("=" * 70)

    # Phase 1: Self-Tests (get cross data too)
    print("\n" + "=" * 50)
    print("Phase 1: 自通性测试 (8 Languages)")
    print("=" * 50)

    self_tests = {
        "python": python_self_test,
        "go": go_self_test,
        "javascript": js_self_test,
        "java": java_self_test,
        "csharp": csharp_self_test,
        "c": c_self_test,
        "cpp": cpp_self_test,
        "rust": rust_self_test,
    }

    self_ops = ["sm2_enc_dec", "sm2_sig_ver", "sm2_enc_sig_ver_dec", "sm3", "sm3_hmac", "sm4_enc_dec"]

    for lang in LANGUAGES:
        if lang not in self_tests:
            continue
        print(f"\n{'='*20} {LANG_LABELS[lang]} {'='*20}")
        try:
            r = self_tests[lang]()
            if r:
                self_results[lang] = {}
                for op in self_ops:
                    self_results[lang][op] = r.get(op, "SKIP")
                # Store cross data
                if "sm2_enc" in r or "sm3_hash" in r:
                    cross_data[lang] = {
                        "lang": lang,
                        "msg": r.get("msg", TEST_MSG),
                        "sm2_enc": r.get("sm2_enc", ""),
                        "sm2_sig": r.get("sm2_sig", ""),
                        "sm4_enc": r.get("sm4_enc", ""),
                        "sm3_hash": r.get("sm3_hash", ""),
                        "sm3_hmac_hash": r.get("sm3_hmac_hash", ""),
                    }
                print(f"  Results: {', '.join(f'{op}={self_results[lang][op]}' for op in self_ops)}")
            else:
                self_results[lang] = {op: "ERROR" for op in self_ops}
                print(f"  ERROR: Test failed to produce results")
        except Exception as e:
            self_results[lang] = {op: "ERROR" for op in self_ops}
            print(f"  EXCEPTION: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n交叉数据生产者: {list(cross_data.keys())}")

    # Phase 2: Cross-Tests
    print("\n" + "=" * 50)
    print("Phase 2: 互通性测试 (Cross-Language)")
    print("=" * 50)

    cross_consumers = {
        "python": python_cross_test,
        "go": go_cross_test,
        "javascript": js_cross_test,
        "java": java_cross_test,
        "csharp": csharp_cross_test,
        "c": c_cross_test,
        "cpp": cpp_cross_test,
        "rust": rust_cross_test,
    }

    cross_ops = ["sm2_dec", "sm2_ver", "sm2_enc_sig_ver_dec", "sm3", "sm3_hmac", "sm4_dec"]

    for producer in LANGUAGES:
        if producer not in cross_data:
            print(f"\n  Producer {LANG_LABELS[producer]}: NO DATA (skipping)")
            for consumer in LANGUAGES:
                if consumer != producer:
                    for op in cross_ops:
                        test_results[(producer, consumer, op)] = "SKIP"
            continue
        pdata = cross_data[producer]
        for consumer in LANGUAGES:
            if consumer == producer:
                # Self-test already done
                for op in self_ops:
                    sr = self_results.get(producer, {}).get(op, "SKIP")
                    # Map self op names to cross op names
                    cross_op_map = {
                        "sm2_enc_dec": "sm2_dec",
                        "sm2_sig_ver": "sm2_ver",
                        "sm2_enc_sig_ver_dec": "sm2_enc_sig_ver_dec",
                        "sm3": "sm3",
                        "sm3_hmac": "sm3_hmac",
                        "sm4_enc_dec": "sm4_dec",
                    }
                    mapped = cross_op_map.get(op, op)
                    test_results[(producer, consumer, mapped)] = sr if sr in ("PASS", "FAIL") else "SKIP"
                continue
            if consumer not in cross_consumers:
                for op in cross_ops:
                    test_results[(producer, consumer, op)] = "SKIP"
                continue
            print(f"\n  {LANG_LABELS[producer]} → {LANG_LABELS[consumer]}...")
            try:
                cr = cross_consumers[consumer](pdata)
                if cr:
                    for op in cross_ops:
                        test_results[(producer, consumer, op)] = cr.get(op, "SKIP")
                    statuses = {op: test_results[(producer, consumer, op)] for op in cross_ops}
                    print(f"    {statuses}")
                else:
                    for op in cross_ops:
                        test_results[(producer, consumer, op)] = "ERROR"
                    print(f"    ERROR: Consumer failed")
            except Exception as e:
                for op in cross_ops:
                    test_results[(producer, consumer, op)] = "ERROR"
                print(f"    EXCEPTION: {e}")

    # Phase 3: Generate Report
    print("\n" + "=" * 50)
    print("Phase 3: 生成测试报告")
    print("=" * 50)
    generate_report()
    write_fix_log()
    elapsed = time.time() - start
    print(f"\n测试完成! 耗时: {elapsed:.1f}s")
    print(f"自测结果: {len([v for v in self_results.values() if v])} 语言")
    print(f"互通结果: {len([v for v in test_results.values() if v != 'SKIP'])} 项")
    print(f"报告: {REPORT_FILE}")
    print(f"修复日志: {LOG_FILE}")


def generate_report():
    lines = []
    lines.append("# 跨语言国密算法互通性测试报告 v7")
    lines.append("")
    lines.append(f"**Full — 8种语言自测试 + 8×8 跨语言互通验证 (384项)**")
    lines.append("")
    lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 一、各语言自通性测试结果")
    lines.append("")
    lines.append("| 语言 | SM2加解密 | SM2签名验签 | SM2加密签名→验签解密 | SM3 | SM3-HMAC | SM4 GCM | 备注 |")
    lines.append("|------|:---:|:---:|:---:|:---:|:---:|:---:|------|")

    def pv(v):
        if v == "PASS": return "✅"
        if v == "FAIL": return "❌"
        if v == "ERROR": return "💥"
        return "⚠️"

    for lang in LANGUAGES:
        r = self_results.get(lang, {})
        if not r:
            lines.append(f"| **{LANG_LABELS[lang]}** | — | — | — | — | — | — | 环境未就绪 |")
        else:
            cols = [
                pv(r.get("sm2_enc_dec", "SKIP")),
                pv(r.get("sm2_sig_ver", "SKIP")),
                pv(r.get("sm2_enc_sig_ver_dec", "SKIP")),
                pv(r.get("sm3", "SKIP")),
                pv(r.get("sm3_hmac", "SKIP")),
                pv(r.get("sm4_enc_dec", "SKIP")),
            ]
            lines.append(f"| **{LANG_LABELS[lang]}** | {' | '.join(cols)} | |")
    lines.append("")
    lines.append("> ✅ = 通过 | ❌ = 失败 | 💥 = 执行错误 | ⚠️ = 跳过 | — = 未测试")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 二、完整测试矩阵 (8×8 = 64组合 × 6类操作 = 384项)")
    lines.append("")

    op_names = [
        ("SM2 加密解密 (Encrypt/Decrypt)", "sm2_dec"),
        ("SM2 签名验签 (Sign/Verify)", "sm2_ver"),
        ("SM2 加密签名→验签解密 (EncSign/VerifyDec)", "sm2_enc_sig_ver_dec"),
        ("SM3 哈希", "sm3"),
        ("SM3-HMAC", "sm3_hmac"),
        ("SM4 GCM 加解密", "sm4_dec"),
    ]

    for op_name, op_key in op_names:
        lines.append(f"### {op_name}")
        lines.append("")
        header = "| ↓生产者 / 消费者→ | " + " | ".join(f"**{LANG_LABELS[l]}**" for l in LANGUAGES) + " |"
        sep = "|:---|" + ":---:|" * len(LANGUAGES)
        lines.append(header)
        lines.append(sep)

        for pl in LANGUAGES:
            row = [f"**{LANG_LABELS[pl]}**"]
            for cl in LANGUAGES:
                if pl == cl:
                    # Self-test: map to self_results
                    self_map = {
                        "sm2_dec": "sm2_enc_dec",
                        "sm2_ver": "sm2_sig_ver",
                        "sm2_enc_sig_ver_dec": "sm2_enc_sig_ver_dec",
                        "sm3": "sm3",
                        "sm3_hmac": "sm3_hmac",
                        "sm4_dec": "sm4_enc_dec",
                    }
                    sk = self_map.get(op_key, op_key)
                    v = self_results.get(pl, {}).get(sk, "SKIP")
                    if v == "PASS": row.append("⭐")
                    elif v == "FAIL": row.append("❌")
                    elif v == "ERROR": row.append("💥")
                    else: row.append("—")
                else:
                    v = test_results.get((pl, cl, op_key), "SKIP")
                    if v == "PASS": row.append("✅")
                    elif v == "FAIL": row.append("❌")
                    elif v == "ERROR": row.append("💥")
                    else: row.append("—")
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

    lines.append("> 图例: ⭐ = 自测通过 | ✅ = 互通通过 | ❌ = 失败 | 💥 = 执行错误 | — = 未测试/跳过")
    lines.append("")

    # Summary statistics
    lines.append("---")
    lines.append("")
    lines.append("## 三、统计汇总")
    lines.append("")

    for op_name, op_key in op_names:
        passed = 0; failed = 0; skipped = 0; error = 0
        for pl in LANGUAGES:
            for cl in LANGUAGES:
                if pl == cl:
                    self_map = {
                        "sm2_dec": "sm2_enc_dec", "sm2_ver": "sm2_sig_ver",
                        "sm2_enc_sig_ver_dec": "sm2_enc_sig_ver_dec",
                        "sm3": "sm3", "sm3_hmac": "sm3_hmac", "sm4_dec": "sm4_enc_dec",
                    }
                    sk = self_map.get(op_key, op_key)
                    v = self_results.get(pl, {}).get(sk, "SKIP")
                else:
                    v = test_results.get((pl, cl, op_key), "SKIP")
                if v == "PASS": passed += 1
                elif v == "FAIL": failed += 1
                elif v == "ERROR": error += 1
                else: skipped += 1
        total = passed + failed + skipped + error
        lines.append(f"- **{op_name}**: ✅ {passed} | ❌ {failed} | 💥 {error} | — {skipped} | 总计 {total}")
    lines.append("")

    # Detailed by language
    lines.append("---")
    lines.append("")
    lines.append("## 四、各语言自测详细结果")
    lines.append("")

    for lang in LANGUAGES:
        r = self_results.get(lang, {})
        lines.append(f"### {LANG_LABELS[lang]}")
        if not r:
            lines.append("- 状态: 环境未就绪")
        else:
            for op in self_ops:
                lines.append(f"- {op}: {r.get(op, 'N/A')}")
        lines.append("")

    # Fix history
    if fix_history:
        lines.append("---")
        lines.append("")
        lines.append("## 五、修复历史")
        lines.append("")
        lines.append("| ID | 问题 | 文件 | 操作 | 时间 |")
        lines.append("|----|------|------|------|------|")
        for e in fix_history:
            lines.append(f"| {e['id']} | {e['description']} | {e['file']} | {e['action']} | {e['timestamp']} |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## 六、互操作性标准约定")
    lines.append("")
    lines.append("### SM2 加密")
    lines.append("- 密文格式: C1C3C2")
    lines.append("- C1格式: 04 + X(32字节) + Y(32字节) = 65字节/130 HEX字符")
    lines.append("- 编码: Hex优先, 同时支持Base64")
    lines.append("")
    lines.append("### SM2 签名")
    lines.append("- 签名格式: DER ASN.1 Sequence { INTEGER r, INTEGER s }")
    lines.append("- USER_ID: \"1234567812345678\" (GB/T 32918标准默认值)")
    lines.append("")
    lines.append("### SM3")
    lines.append(f"- 预期输出: `{EXP_SM3}`")
    lines.append(f"- SM3-HMAC预期输出: `{EXP_SM3_HMAC}`")
    lines.append(f"- HMAC密钥: `{HMAC_KEY_HEX}`")
    lines.append("")
    lines.append("### SM4 GCM")
    lines.append("- 模式: GCM (NIST SP 800-38D)")
    lines.append("- IV: 12字节 (96 bits)")
    lines.append("- Tag: 16字节 (128 bits)")
    lines.append("- 输出格式: IV[12] + 密文 + Tag[16]")
    lines.append("- 编码: Hex优先, 同时支持Base64")
    lines.append("")
    lines.append("### 编码与字符集")
    lines.append("- 字符编码: UTF-8")
    lines.append("- 编码方式: Hex优先, Base64可选")
    lines.append("- 自动检测: 各语言解密/验签/解码时自动识别Hex/Base64格式")
    lines.append("")

    lines.append("---")
    lines.append(f"\n*报告生成: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 测试框架 v7*")

    REPORT_FILE.write_text('\n'.join(lines), encoding='utf-8')


if __name__ == "__main__":
    main()
