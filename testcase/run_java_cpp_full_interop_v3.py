#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Java ↔ C++ SM2/SM3/SM4 双向互通性测试 v3
统一通过 hex encoding 传递非ASCII数据，规避 Windows cmdline 编码问题。
"""

import json, os, sys, subprocess
from pathlib import Path
from datetime import datetime

BASE_DIR    = Path("G:/workspaces/git/corssmool/crossmool")
CPP_EXE     = BASE_DIR / "cpp/crossmool/build/bin/Release/interoperability_test.exe"
TEMP_DIR    = BASE_DIR / "testcase/.interop_temp"
RESULT_DIR  = BASE_DIR / "testcase/results"

JAVA_CP = (
    f"{BASE_DIR}/testcase/java_test_classes;"
    f"{BASE_DIR}/java/crossmool/target/classes;"
    f"{BASE_DIR}/java/crossmool/target/dependency/bcprov-jdk18on-1.82.jar;"
    f"{BASE_DIR}/java/crossmool/target/dependency/lombok-1.18.42.jar;"
    f"{BASE_DIR}/java/crossmool/target/dependency/slf4j-api-2.0.17.jar;"
    f"{BASE_DIR}/java/crossmool/target/dependency/logback-classic-1.5.22.jar;"
    f"{BASE_DIR}/java/crossmool/target/dependency/logback-core-1.5.22.jar"
)

TEST_MSGS = [
    "Hello, Cross-Language Interop Test!",
    "国密算法跨语言互通测试：简体中文",
    "Mixed content 123!@#$% 混合測試數據",
]
MSG_HEX = {m: m.encode('utf-8').hex() for m in TEST_MSGS}
HMAC_HEX = "0123456789abcdef0123456789abcdef"
SM4_KEY  = "8091d00c09ba74cfe6da26b7daa7ce39"

results = []; p = f = 0

def java(args, to=60):
    cmd = ["java", "-Dfile.encoding=UTF-8", "-Dsun.stdout.encoding=UTF-8", "-Dsun.stderr.encoding=UTF-8",
           "-cp", JAVA_CP, "java_test_classes.JavaCLIHelper"] + args
    try:
        r = subprocess.run(cmd, cwd=str(BASE_DIR/"testcase"),
            capture_output=True, text=True, timeout=to, encoding='utf-8', errors='replace')
        o = r.stdout
        if "__RESULT_OK__" in o:
            return True, o[:o.index("__RESULT_OK__")].strip()
        return r.returncode == 0, o.strip()
    except: return False, ""

def cpp(args, to=60):
    try:
        r = subprocess.run([str(CPP_EXE)]+args, cwd=str(TEMP_DIR),
            capture_output=True, text=True, timeout=to, encoding='utf-8', errors='replace')
        return r.returncode == 0, r.stdout, r.stderr
    except: return False, "", ""

def wt(name, content):
    TEMP_DIR.mkdir(parents=True, exist_ok=True)
    p = TEMP_DIR / name
    with open(p, 'w', encoding='utf-8') as f: f.write(content)
    return str(p)

def rtj(name):
    with open(TEMP_DIR / name, 'r', encoding='utf-8') as f: return json.load(f)

def js(obj): return json.dumps(obj, ensure_ascii=False, indent=2)

def mk(**kw):
    d = {}
    for k, v in kw.items(): d[k] = {"hex": v}
    return d

def record(algo, op, dir_, ok, detail=""):
    global p, f
    s = "PASS" if ok else "FAIL"
    if ok: p += 1
    else: f += 1
    results.append({"algorithm": algo, "operation": op, "direction": dir_, "status": s, "details": detail})
    print(f"  [{s}] {algo} {op} ({dir_}): {detail}")

def der_to_c1c3c2(hex_ct):
    data = bytes.fromhex(hex_ct)
    if data[0] != 0x30: raise ValueError(f"Not DER: {hex(data[0])}")
    pos = 2
    if data[1] >= 0x80: pos += data[1] - 0x80
    def rdt(tag):
        nonlocal pos
        assert data[pos] == tag, f"tag mismatch at {pos}"
        pos += 1; l = data[pos]; pos += 1
        if l >= 0x80: e = l-0x80; l = int.from_bytes(data[pos:pos+e],'big'); pos += e
        v = data[pos:pos+l]; pos += l; return v
    xr = rdt(0x02); yr = rdt(0x02); c3 = rdt(0x04); c2 = rdt(0x04)
    def i32(v):
        while len(v)>1 and v[0]==0: v=v[1:]
        return b'\x00'*(32-len(v))+v if len(v)<32 else v
    x=i32(xr); y=i32(yr)
    if len(c3)<32: c3=b'\x00'*(32-len(c3))+c3
    return (b'\x04'+x+y+c3+c2).hex()

# ======== Phase 1: Gen Keypair ========
print("="*60); print("Phase 1: Generate SM2 Key Pair"); print("="*60)
ok, data = java(["gen-keypair"])
assert ok, "gen-keypair failed"
ki = json.loads(data); PUB=ki["public_key"]; PRV=ki["private_key"]
print(f"Pub: {PUB[:40]}...")

# ======== Phase 2: SM2 Enc/Dec Bidirectional ========
print("\n"+"="*60); print("Phase 2: SM2 Encrypt/Decrypt"); print("="*60)
for m in TEST_MSGS:
    mh = MSG_HEX[m]; short = m[:30].replace('\n','\\n')

    # Java→C++ (use string encrypt since Java CLI handles it, then C++ decrypts)
    okj, jct = java(["sm2-encrypt", m, PUB])
    if okj:
        ct_in = js({"ciphertext_hex": jct}); wt("_ct.json", ct_in)
        okc, _, cerr = cpp(["decrypt", str(TEMP_DIR/"_ct.json"), wt("_ek.json", js(mk(encryption_private_key=PRV))), str(TEMP_DIR/"_dec.json")])
        if okc:
            dec = rtj("_dec.json"); match = (dec.get("plaintext","") == m)
        else: match = False; dec = {"plaintext": f"C++err:{cerr[:80]}"}
    else:
        match = False; dec = {"plaintext": f"JavaErr:{jct[:80]}"}
    record("SM2","enc/dec","Java→C++", match,
           f"#{TEST_MSGS.index(m)+1} {short}" + (f" [{dec.get('plaintext','')[:20]}]" if not match else ""))

    # C++→Java: C++ encrypts bytes from file, DER→C1C3C2, Java decrypts via hex mode
    wt("_pt.txt", m)
    okc, _, cerr = cpp(["encrypt", str(TEMP_DIR/"_pt.txt"), wt("_ek2.json", js(mk(encryption_public_key=PUB))), str(TEMP_DIR/"_enc.json")])
    if okc:
        cct_der = rtj("_enc.json")["ciphertext_hex"]
        try: c1c3c2 = der_to_c1c3c2(cct_der)
        except Exception as e:
            record("SM2","enc/dec","C++→Java", False, f"#{TEST_MSGS.index(m)+1} DERconv:{e}"); continue
        # Java decrypt-hex: returns hex plaintext
        okj, jpt_hex = java(["sm2-decrypt-hex", c1c3c2, PRV])
        if okj:
            try: jpt = bytes.fromhex(jpt_hex).decode('utf-8')
            except: jpt = f"HEX:{jpt_hex[:30]}"
            match = (jpt == m)
        else: jpt = f"JavaErr:{jpt_hex[:50]}"; match = False
    else:
        match = False; jpt = f"C++err:{cerr[:80]}"
    record("SM2","enc/dec","C++→Java", match,
           f"#{TEST_MSGS.index(m)+1} {short}" + (f" [{jpt[:20]}]" if not match else ""))

# ======== Phase 3: SM2 Sign/Verify ========
print("\n"+"="*60); print("Phase 3: SM2 Sign/Verify"); print("="*60)
for m in TEST_MSGS:
    short = m[:30].replace('\n','\\n'); idx = TEST_MSGS.index(m)+1

    # Java→C++
    okj, jsig = java(["sm2-sign", m, PRV])
    if okj:
        vi = js({"content": m, "signature_hex": jsig}); wt("_vi.json", vi)
        okc, _, cerr = cpp(["verify", str(TEMP_DIR/"_vi.json"), wt("_vk.json", js(mk(signature_public_key=PUB))), str(TEMP_DIR/"_vo.json")])
        match = okc and rtj("_vo.json").get("verify_result") == True
    else: match = False
    record("SM2","sign/verify","Java→C++", match, f"#{idx} {short}")

    # C++→Java
    wt("_sp.txt", m)
    okc, _, cerr = cpp(["sign", str(TEMP_DIR/"_sp.txt"), wt("_sk.json", js(mk(signature_private_key=PRV))), str(TEMP_DIR/"_so.json")])
    if okc:
        csig = rtj("_so.json")["signature_hex"]
        okj, jv = java(["sm2-verify", m, csig, PUB])
        match = okj and jv.strip().lower() == "true"
    else: match = False
    record("SM2","sign/verify","C++→Java", match, f"#{idx} {short}")

# ======== Phase 4: SM2 EncSign/VerDec ========
print("\n"+"="*60); print("Phase 4: SM2 EncryptSign/VerifyDecrypt"); print("="*60)
for m in TEST_MSGS:
    short = m[:30].replace('\n','\\n'); idx = TEST_MSGS.index(m)+1

    # Java→C++
    ok_e, jct = java(["sm2-encrypt", m, PUB])
    ok_s, jsig = java(["sm2-sign", jct if ok_e else m, PRV])
    if ok_e and ok_s:
        vd = js({"ciphertext_hex": jct, "signature_hex": jsig}); wt("_vd.json", vd)
        okc, _, cerr = cpp(["verify_decrypt", str(TEMP_DIR/"_vd.json"), wt("_vdk.json", js(mk(encryption_private_key=PRV, signature_public_key=PUB))), str(TEMP_DIR/"_vdo.json")])
        if okc:
            vdo = rtj("_vdo.json"); match = vdo.get("verify_result")==True and vdo.get("decrypted_text")==m
        else: match = False
    else: match = False
    record("SM2","enc_sign/ver_dec","Java→C++", match, f"#{idx} {short}")

    # C++→Java: C++ signs HEX STRING of DER ciphertext
    wt("_esp.txt", m)
    okc, _, cerr = cpp(["encrypt_sign", str(TEMP_DIR/"_esp.txt"), wt("_esk.json", js(mk(encryption_public_key=PUB, signature_private_key=PRV))), str(TEMP_DIR/"_eso.json")])
    if okc:
        eso = rtj("_eso.json"); cct_der = eso["ciphertext_hex"]; csig = eso["signature_hex"]
        # Verify: C++ signed DER hex string as UTF-8 bytes
        ok_v, jv = java(["sm2-verify", cct_der, csig, PUB])
        if ok_v and jv.strip().lower() == "true":
            try: c1c3c2 = der_to_c1c3c2(cct_der)
            except Exception as e:
                record("SM2","enc_sign/ver_dec","C++→Java", False, f"#{idx} DER:{e}"); continue
            ok_d, jpt_hex = java(["sm2-decrypt-hex", c1c3c2, PRV])
            if ok_d:
                try: jpt = bytes.fromhex(jpt_hex).decode('utf-8')
                except: jpt = f"HEX:{jpt_hex[:20]}"
                match = (jpt == m)
            else: match = False
        else: match = False
    else: match = False
    record("SM2","enc_sign/ver_dec","C++→Java", match, f"#{idx} {short}")

# ======== Phase 5: SM3 Digest ========
print("\n"+"="*60); print("Phase 5: SM3 Digest"); print("="*60)
for m in TEST_MSGS:
    short=m[:30]; idx=TEST_MSGS.index(m)+1
    okj, jd = java(["sm3-digest", m])
    okc, _, _ = cpp(["sm3_digest", wt("_sm3.txt", m), str(TEMP_DIR/"_sm3.json")])
    if okc: cd = rtj("_sm3.json")["digest_hex"]
    else: cd = ""
    record("SM3","digest","Java↔C++", okc and jd==cd, f"#{idx} {short} J={jd[:12]}... C={cd[:12]}...")

# ======== Phase 6: HMAC-SM3 ========
print("\n"+"="*60); print("Phase 6: HMAC-SM3"); print("="*60)
for m in TEST_MSGS:
    short=m[:30]; idx=TEST_MSGS.index(m)+1
    okj, jh = java(["sm3-hmac", HMAC_HEX, m])
    hi = js({"hmac_key_hex": HMAC_HEX, "data": m}); wt("_hi.json", hi)
    okc, _, _ = cpp(["sm3_hmac", str(TEMP_DIR/"_hi.json"), str(TEMP_DIR/"_ho.json")])
    if okc: ch = rtj("_ho.json")["hmac_hex"]
    else: ch = ""
    record("HMAC-SM3","hmac","Java↔C++", okc and jh==ch, f"#{idx} {short} J={jh[:12]}... C={ch[:12]}...")

# ======== Phase 7: SM4 Enc/Dec ========
print("\n"+"="*60); print("Phase 7: SM4 Encrypt/Decrypt"); print("="*60)
for m in TEST_MSGS:
    short=m[:30]; idx=TEST_MSGS.index(m)+1

    # Java→C++
    okj, jct = java(["sm4-encrypt", m, SM4_KEY])
    if okj:
        in_j = js({"ciphertext_hex": jct, "sm4_key_hex": SM4_KEY}); wt("_s4di.json", in_j)
        okc, _, cerr = cpp(["sm4_decrypt", str(TEMP_DIR/"_s4di.json"), str(TEMP_DIR/"_s4do.json")])
        match = okc and rtj("_s4do.json").get("plaintext","") == m
    else: match = False
    record("SM4","enc/dec","Java→C++", match, f"#{idx} {short}")

    # C++→Java
    in_c = js({"plaintext": m, "sm4_key_hex": SM4_KEY}); wt("_s4ei.json", in_c)
    okc, _, cerr = cpp(["sm4_encrypt", str(TEMP_DIR/"_s4ei.json"), str(TEMP_DIR/"_s4eo.json")])
    if okc:
        cct = rtj("_s4eo.json")["ciphertext_hex"]
        okj, jp = java(["sm4-decrypt", cct, SM4_KEY])
        match = okj and jp == m
    else: match = False
    record("SM4","enc/dec","C++→Java", match, f"#{idx} {short}" + (f" [{jp[:30]}]" if not match and okc else ""))

# ======== Summary ========
t = p+f; rate = p/t*100 if t else 0
print("\n"+"="*60); print("FINAL SUMMARY"); print("="*60)
print(f"  Total: {t}  PASS: {p}  FAIL: {f}  Rate: {rate:.1f}%")

RESULT_DIR.mkdir(parents=True, exist_ok=True)
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
rf = RESULT_DIR / f"java_cpp_full_interop_v3_{ts}.json"
with open(rf, 'w', encoding='utf-8') as fp:
    json.dump({"time": datetime.now().isoformat(), "total": t, "passed": p, "failed": f,
        "rate": f"{rate:.1f}%", "results": results}, fp, indent=2, ensure_ascii=False)
print(f"Results: {rf}")
sys.exit(0 if f==0 else 1)
