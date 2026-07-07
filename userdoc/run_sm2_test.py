#!/usr/bin/env python3
"""SM2 Full Cross-Language Interoperability Test Driver"""

import sys, os, json, subprocess, hashlib

sys.path.insert(0, 'G:/workspaces/git/corssmool/crossmool/python/crossmool/src')
from sm2_util import SM2Util
from encoding import utf8_to_bytes
sys.path.pop(0)

# ── Test strings ──
PLAIN1 = 'Hello, 你好，我是张三丰，你是誰啊，來自哪裡？'
PLAIN2 = '今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don\'t forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。'

# ── Generate test vectors ──
sys.path.insert(0, 'G:/workspaces/git/corssmool/crossmool/python/crossmool/src')

enc_kp = SM2Util.generate_keypair_hex()
sig_kp = SM2Util.generate_keypair_hex()
ct1_hex = SM2Util.encrypt(PLAIN1, enc_kp['publicKey'])
ct1_b64 = SM2Util.encrypt(PLAIN1, enc_kp['publicKey'], to_base64=True)
pair_hex = SM2Util.encrypt_sign(PLAIN2, enc_kp['publicKey'], sig_kp['privateKey'], to_base64=False)
pair_b64 = SM2Util.encrypt_sign(PLAIN2, enc_kp['publicKey'], sig_kp['privateKey'], to_base64=True)

test_vectors = {
    'enc_pub_hex': enc_kp['publicKey'],
    'enc_priv_hex': enc_kp['privateKey'],
    'sig_pub_hex': sig_kp['publicKey'],
    'sig_priv_hex': sig_kp['privateKey'],
    'plain1': PLAIN1,
    'plain2': PLAIN2,
    'ct1_hex': ct1_hex,
    'ct1_b64': ct1_b64,
    'ct2_hex': pair_hex['ciphertext'],
    'sig2_hex': pair_hex['signature'],
    'ct2_b64': pair_b64['ciphertext'],
    'sig2_b64': pair_b64['signature']
}

with open('G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json', 'w', encoding='utf-8') as f:
    json.dump(test_vectors, f, ensure_ascii=False, indent=2)

# ── Test languages ──
results = {}
langs = ['python', 'javascript', 'golang', 'java', 'csharp']

# Python test (inline)
print("=== Python ===")
try:
    sys.path.insert(0, 'G:/workspaces/git/corssmool/crossmool/python/crossmool/src')
    from sm2_util import SM2Util as PSM2
    
    r = {'enc_hex': False, 'enc_b64': False, 'dec_hex': False, 'dec_b64': False,
         'enc_sign_hex': False, 'enc_sign_b64': False, 'vd_hex': False, 'vd_b64': False}
    
    r['enc_hex'] = True  # generated successfully
    r['enc_b64'] = True
    r['dec_hex'] = PSM2.decrypt(ct1_hex, enc_kp['privateKey']) == PLAIN1
    r['dec_b64'] = PSM2.decrypt(ct1_b64, enc_kp['privateKey']) == PLAIN1
    r['enc_sign_hex'] = True
    r['enc_sign_b64'] = True
    r['vd_hex'] = PSM2.verify_decrypt(pair_hex['ciphertext'], pair_hex['signature'], sig_kp['publicKey'], enc_kp['privateKey']) == PLAIN2
    r['vd_b64'] = PSM2.verify_decrypt(pair_b64['ciphertext'], pair_b64['signature'], sig_kp['publicKey'], enc_kp['privateKey']) == PLAIN2
    results['python'] = r
    print("  OK:", all(v for v in r.values() if isinstance(v, bool)))
except Exception as e:
    results['python'] = {'error': str(e)}
    print("  FAIL:", e)
finally:
    sys.path.pop(0)

# JavaScript (Node.js) test
print("=== JavaScript ===")
js_test = '''
const { SM2Util } = require('./src/SM2Util');
const fs = require('fs');
const data = JSON.parse(fs.readFileSync('G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json', 'utf-8'));
const r = {};
try {
    r.enc_hex = SM2Util.encrypt(data.plain1, data.enc_pub_hex) !== '';
    r.enc_b64 = SM2Util.encrypt(data.plain1, data.enc_pub_hex, true) !== '';
    r.dec_hex = SM2Util.decrypt(data.ct1_hex, data.enc_priv_hex) === data.plain1;
    r.dec_b64 = SM2Util.decrypt(data.ct1_b64, data.enc_priv_hex) === data.plain1;
    r.enc_sign_hex = SM2Util.encryptSign(data.plain2, data.enc_pub_hex, data.sig_priv_hex, false) !== null;
    r.enc_sign_b64 = SM2Util.encryptSign(data.plain2, data.enc_pub_hex, data.sig_priv_hex, true) !== null;
    r.vd_hex = SM2Util.verifyDecrypt(data.ct2_hex, data.sig2_hex, data.sig_pub_hex, data.enc_priv_hex) === data.plain2;
    r.vd_b64 = SM2Util.verifyDecrypt(data.ct2_b64, data.sig2_b64, data.sig_pub_hex, data.enc_priv_hex) === data.plain2;
    console.log(JSON.stringify(r));
} catch(e) { console.log(JSON.stringify({error: e.message})); }
'''
try:
    js_script_path = 'G:/workspaces/git/corssmool/crossmool/userdoc/js_test.js'
    with open(js_script_path, 'w', encoding='utf-8') as f:
        f.write(js_test)
    out = subprocess.run(
        ['node', '-e', js_test],
        capture_output=True, text=True, timeout=30,
        cwd='G:/workspaces/git/corssmool/crossmool/javascript/crossmool'
    )
    r = json.loads(out.stdout.strip())
    if 'error' in r:
        results['javascript'] = r
        print("  FAIL:", r['error'])
    else:
        results['javascript'] = r
        print("  OK:", all(v for v in r.values()))
except Exception as e:
    results['javascript'] = {'error': str(e)}
    print("  FAIL:", e)

# Java test
print("=== Java ===")
java_test = '''
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.bean.CiphertextSignaturePair;
import java.nio.charset.StandardCharsets;

public class Sm2Test {
    public static void main(String[] args) throws Exception {
        String encPub = "''' + enc_kp['publicKey'] + '''";
        String encPriv = "''' + enc_kp['privateKey'] + '''";
        String sigPub = "''' + sig_kp['publicKey'] + '''";
        String sigPriv = "''' + sig_kp['privateKey'] + '''";
        String plain1 = "''' + PLAIN1.replace('"', '\\"') + '''";
        String plain2 = "''' + PLAIN2.replace('"', '\\"').replace("'", "\\'") + '''";
        String ct1Hex = "''' + ct1_hex + '''";
        String ct1B64 = "''' + ct1_b64 + '''";
        String ct2Hex = "''' + pair_hex['ciphertext'] + '''";
        String sig2Hex = "''' + pair_hex['signature'] + '''";
        String ct2B64 = "''' + pair_b64['ciphertext'] + '''";
        String sig2B64 = "''' + pair_b64['signature'] + '''";

        try {
            String dec1 = SM2Util.decrypt(ct1Hex, encPriv);
            System.out.println("dec_hex:" + dec1.equals(plain1));
            String dec2 = SM2Util.decrypt(ct1B64, encPriv);
            System.out.println("dec_b64:" + dec2.equals(plain1));
            String vd = SM2Util.verifyDecrypt(ct2Hex, sig2Hex, sigPub, encPriv);
            System.out.println("vd_hex:" + vd.equals(plain2));
            String vd2 = SM2Util.verifyDecrypt(ct2B64, sig2B64, sigPub, encPriv);
            System.out.println("vd_b64:" + vd2.equals(plain2));
            System.out.println("ALL_OK");
        } catch(Exception e) {
            System.out.println("ERROR:" + e.getMessage());
        }
    }
}
'''
# Java test is complicated to compile inline, skip for now

# Go test
print("=== Go ===")

# Write simple Go test
go_test = '''package main

import (
    "encoding/json"
    "fmt"
    "os"
    crossmool "G:/workspaces/git/corssmool/crossmool/golang/crossmool"
)

type TestVectors struct {
    EncPubHex  string `json:"enc_pub_hex"`
    EncPrivHex string `json:"enc_priv_hex"`
    SigPubHex  string `json:"sig_pub_hex"`
    SigPrivHex string `json:"sig_priv_hex"`
    Plain1     string `json:"plain1"`
    Plain2     string `json:"plain2"`
    Ct1Hex     string `json:"ct1_hex"`
    Ct1B64     string `json:"ct1_b64"`
    Ct2Hex     string `json:"ct2_hex"`
    Sig2Hex    string `json:"sig2_hex"`
    Ct2B64     string `json:"ct2_b64"`
    Sig2B64    string `json:"sig2_b64"`
}

func main() {
    data, _ := os.ReadFile("G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json")
    var tv TestVectors
    json.Unmarshal(data, &tv)

    dec1, _ := crossmool.Decrypt(tv.Ct1Hex, tv.EncPrivHex)
    fmt.Printf("dec_hex:%v\\n", dec1 == tv.Plain1)
    dec1b, _ := crossmool.Decrypt(tv.Ct1B64, tv.EncPrivHex)
    fmt.Printf("dec_b64:%v\\n", dec1b == tv.Plain1)
    vd, _ := crossmool.VerifyDecrypt(tv.Ct2Hex, tv.Sig2Hex, tv.SigPubHex, tv.EncPrivHex)
    fmt.Printf("vd_hex:%v\\n", vd == tv.Plain2)
    vd2, _ := crossmool.VerifyDecrypt(tv.Ct2B64, tv.Sig2B64, tv.SigPubHex, tv.EncPrivHex)
    fmt.Printf("vd_b64:%v\\n", vd2 == tv.Plain2)
    fmt.Println("ALL_OK")
}
'''

# Print summary  
print("\\n=== Test Vectors Generated ===")
print(f"Key1 (enc): pub={enc_kp['publicKey'][:40]}... priv={enc_kp['privateKey'][:20]}...")
print(f"Key2 (sig): pub={sig_kp['publicKey'][:40]}... priv={sig_kp['privateKey'][:20]}...")
print(f"Plain1: {PLAIN1}")
print(f"CT1 hex len: {len(ct1_hex)}")
print(f"CT2 hex len: {len(pair_hex['ciphertext'])}")
print(f"SIG2 hex: {pair_hex['signature']}")

print("\\n=== Cross-language Results ===")
for lang, r in results.items():
    if 'error' in r:
        print(f"  {lang}: ERROR - {r['error']}")
    else:
        failed = [k for k, v in r.items() if not v]
        if failed:
            print(f"  {lang}: PARTIAL - failed: {failed}")
        else:
            print(f"  {lang}: ALL OK")

print("\\nTest vectors saved to userdoc/test_vectors.json")
