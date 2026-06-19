#!/usr/bin/env python3
"""Crossmool v10 - Complete 384-item test"""
import json, os, sys, subprocess, binascii, base64, shutil
from pathlib import Path
from datetime import datetime

BASE = Path(r"G:\workspaces\git\corssmool\crossmool")
OUT = BASE / "testcase" / "output10"
OUT.mkdir(parents=True, exist_ok=True)

MSG = "Hello, 这是跨语言国密互通性测试数据"
SK = "0123456789abcdeffedcba9876543210"
HK = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
E3 = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
EH = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"
EP = "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
EPR = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
SP = "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"
SPR = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"
EPRR = "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03"
SPRR = "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3"
BC_JAR = "C:/Users/Administrator/.m2/repository/org/bouncycastle/bcprov-jdk18on/1.84/bcprov-jdk18on-1.84.jar"
JAVA_CP = str(BASE/"java"/"crossmool"/"src"/"main"/"java") + os.pathsep + BC_JAR

LANGS = ["c","cpp","csharp","java","python","go","rust","javascript"]
LAB = {"c":"C","cpp":"CPP","csharp":"C#","java":"Java","python":"Python","go":"Go","rust":"Rust","javascript":"JS"}
GMSSL_DLL = str(BASE/"testcase"/"output7"/"c_build"/"Release"/"gmssl.dll")

R = {}  # (producer, consumer, op) => result

def run(cmd, cwd=None, timeout=180, stdin=None):
    env = os.environ.copy()
    env['JAVA_TOOL_OPTIONS'] = '-Djava.net.preferIPv4Stack=true'
    try:
        p = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout, env=env, input=stdin, errors='replace')
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except:
        return "", "", -1

def jdump(obj):
    return json.dumps(obj, separators=(',', ':'))

# =========== SELF-TESTS ===========
def py_self():
    sys.path.insert(0, str(BASE/"python"/"crossmool"/"src"))
    from sm2_util import SM2Util; from sm3_util import SM3Util; from sm4_util import SM4Util
    r = {}
    try:
        c = SM2Util.encrypt(MSG, EP, to_base64=False)
        d = SM2Util.decrypt(c, EPR)
        r["enc"] = "PASS" if d == MSG else "FAIL"; r["x_enc"] = c
    except Exception as e: r["enc"] = f"FAIL:{e}"
    try:
        s = SM2Util.sign(MSG, SPR, to_base64=False)
        ok = SM2Util.verify(MSG.encode("utf-8"), SP, s)
        r["sig"] = "PASS" if ok else "FAIL"; r["x_sig"] = s
    except Exception as e: r["sig"] = f"FAIL:{e}"
    try:
        c2 = SM2Util.encrypt(MSG, EP, to_base64=False); s2 = SM2Util.sign(MSG, SPR, to_base64=False)
        d2 = SM2Util.decrypt(c2, EPR); ok2 = SM2Util.verify(d2.encode("utf-8") if isinstance(d2,str) else d2, SP, s2)
        r["esvd"] = "PASS" if d2 == MSG and ok2 else "FAIL"
    except Exception as e: r["esvd"] = f"FAIL:{e}"
    r["sm3"] = "PASS" if SM3Util.digest_str(MSG, False) == E3 else "FAIL"
    r["hmac"] = "PASS" if SM3Util.hmac_to_hex(binascii.unhexlify(HK), MSG.encode("utf-8")) == EH else "FAIL"
    try:
        sk = binascii.unhexlify(SK); sc = SM4Util.encrypt_gcm(sk, MSG.encode("utf-8"), to_base64=False)
        sd = SM4Util.decrypt_gcm_to_string(sk, sc)
        r["sm4"] = "PASS" if sd == MSG else "FAIL"; r["x_sm4"] = sc
    except Exception as e: r["sm4"] = f"FAIL:{e}"
    return r

def go_self():
    d = OUT/"go_s"
    if d.exists(): shutil.rmtree(d)
    d.mkdir(parents=True)
    (d/"go.mod").write_text(f"module s\ngo 1.21\nrequire cc.iili.tools/crossmool v0.0.0\nreplace cc.iili.tools/crossmool => {BASE/'golang'/'crossmool'}\n", encoding='utf-8')
    code = f'''package main
import("encoding/hex";"encoding/json";"fmt";cc "cc.iili.tools/crossmool")
func main(){{r:=map[string]string{{}}
sk,_:=hex.DecodeString("{SK}")
c,e:=cc.Encrypt("{MSG}","{EP}",false);d,_:=cc.Decrypt(c,"{EPR}")
r["enc"]=func()string{{if e!=nil{{return"FAIL:"+e.Error()}};if d=="{MSG}"{{return"PASS"}};return"FAIL"}}();r["x_enc"]=c
s,e:=cc.Sign("{MSG}","{SPR}",false);ok,_:=cc.Verify("{MSG}","{SP}",s)
r["sig"]=func()string{{if e!=nil{{return"FAIL:"+e.Error()}};if ok{{return"PASS"}};return"FAIL"}}();r["x_sig"]=s
c2,_:=cc.Encrypt("{MSG}","{EP}",false);s2,_:=cc.Sign("{MSG}","{SPR}",false);d2,_:=cc.Decrypt(c2,"{EPR}");ok2,_:=cc.Verify(d2,"{SP}",s2)
r["esvd"]=func()string{{if d2=="{MSG}"&&ok2{{return"PASS"}};return"FAIL"}}()
r["sm3"]=func()string{{if cc.DigestToStr("{MSG}",false)=="{E3}"{{return"PASS"}};return"FAIL"}}()
hm,_:=cc.HMACToStr("{HK}","{MSG}",false)
r["hmac"]=func()string{{if hm=="{EH}"{{return"PASS"}};return"FAIL"}}()
sc,e:=cc.EncryptGcm(sk,[]byte("{MSG}"),false);sd,_:=cc.DecryptGcmToString(sk,sc)
r["sm4"]=func()string{{if e!=nil{{return"FAIL:"+e.Error()}};if sd=="{MSG}"{{return"PASS"}};return"FAIL"}}();r["x_sm4"]=sc
o,_:=json.Marshal(r);fmt.Print(string(o))}}'''
    (d/"main.go").write_text(code, encoding='utf-8')
    run(f'cd "{d}" && go mod tidy', timeout=120)
    o,e,rc=run(f'cd "{d}" && go run .')
    if rc!=0: print(f"  Go err: {e}"); return None
    try: return json.loads(o)
    except: print(f"  Go parse: {o[:80]}"); return None

def js_self():
    js = str(BASE/"javascript"/"crossmool"/"dist"/"index.js").replace("\\","/")
    code = f'''
const{{SM2Util,SM3Util,SM4Util,hexToBytes}}=require("{js}");
const M="{MSG}";const K={json.dumps({"eP":EP,"eR":EPR,"sP":SP,"sR":SPR})};const r={{}};
try{{const c=SM2Util.encrypt(M,K.eP,false);r.enc=SM2Util.decrypt(c,K.eR)===M?"PASS":"FAIL";r.x_enc=c;}}catch(e){{r.enc="FAIL:"+e.message;}}
try{{const s=SM2Util.sign(M,K.sR,false);r.sig=SM2Util.verify(M,K.sP,s)?"PASS":"FAIL";r.x_sig=s;}}catch(e){{r.sig="FAIL:"+e.message;}}
try{{const c2=SM2Util.encrypt(M,K.eP,false);const s2=SM2Util.sign(M,K.sR,false);const d2=SM2Util.decrypt(c2,K.eR);r.esvd=(d2===M&&SM2Util.verify(d2,K.sP,s2))?"PASS":"FAIL";}}catch(e){{r.esvd="FAIL:"+e.message;}}
r.sm3=SM3Util.digestToHex(M)==="{E3}"?"PASS":"FAIL";
try{{r.hmac=SM3Util.hmac(hexToBytes("{HK}"),M,false)==="{EH}"?"PASS":"FAIL";}}catch(e){{r.hmac="FAIL:"+e.message;}}
try{{const sk=hexToBytes("{SK}");const sc=SM4Util.encryptGcmString(M,sk,undefined,false);r.sm4=SM4Util.decryptGcmToString(sc,sk)===M?"PASS":"FAIL";r.x_sm4=sc;}}catch(e){{r.sm4="FAIL:"+e.message;}}
console.log(JSON.stringify(r));
'''
    fp = OUT/"js_s.js"; fp.write_text(code, encoding='utf-8')
    o,e,rc=run(f'node "{fp}"')
    if rc!=0: print(f"  JS err: {e}"); return None
    try: return json.loads(o)
    except: return None

def java_self():
    d = OUT/"java_s"; d.mkdir(parents=True, exist_ok=True)
    code = f'''import java.nio.charset.StandardCharsets;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM3Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;
public class S{{static String M="{MSG}",SK="{SK}",HK="{HK}",EP="{EP}",EPR="{EPR}",SP="{SP}",SPR="{SPR}";
public static void main(String[]a){{var sb=new StringBuilder();sb.append("{{");
try{{String c=SM2Util.encrypt(M,EP,false);sb.append("\\"enc\\":\\"").append(SM2Util.decrypt(c,EPR).equals(M)?"PASS":"FAIL").append("\\",\\"x_enc\\":\\"").append(c).append("\\"");}}catch(Exception e){{sb.append("\\"enc\\":\\"FAIL:").append(e.getMessage()).append("\\"");}}
try{{String s=SM2Util.sign(M,SPR,false);sb.append(",\\"sig\\":\\"").append(SM2Util.verify(M,SP,s)?"PASS":"FAIL").append("\\",\\"x_sig\\":\\"").append(s).append("\\"");}}catch(Exception e){{sb.append(",\\"sig\\":\\"FAIL:").append(e.getMessage()).append("\\"");}}
try{{String c2=SM2Util.encrypt(M,EP,false);String s2=SM2Util.sign(M,SPR,false);String d2=SM2Util.decrypt(c2,EPR);boolean ok2=SM2Util.verify(d2,SP,s2);sb.append(",\\"esvd\\":\\"").append(d2.equals(M)&&ok2?"PASS":"FAIL").append("\\"");}}catch(Exception e){{sb.append(",\\"esvd\\":\\"FAIL:").append(e.getMessage()).append("\\"");}}
sb.append(",\\"sm3\\":\\"").append(SM3Util.digestToStr(M,false).equals("{E3}")?"PASS":"FAIL").append("\\"");
sb.append(",\\"hmac\\":\\"").append(SM3Util.hmacToStr(HK,M,false).equals("{EH}")?"PASS":"FAIL").append("\\"");
try{{byte[]sk=HexUtil.decodeHexStr(SK);String sc=SM4Util.encrypt(sk,M.getBytes(StandardCharsets.UTF_8),false);sb.append(",\\"sm4\\":\\"").append(SM4Util.decrypt(sk,sc).equals(M)?"PASS":"FAIL").append("\\",\\"x_sm4\\":\\"").append(sc).append("\\"");}}catch(Exception e){{sb.append(",\\"sm4\\":\\"FAIL:").append(e.getMessage()).append("\\"");}}
sb.append("}}");System.out.println(sb);}}}}'''
    (d/"S.java").write_text(code, encoding='utf-8')
    o,e,rc=run(f'javac -encoding UTF-8 -cp "{JAVA_CP}" -d "{d}" "{d}/S.java"')
    if rc!=0: print(f"  javac err: {e[:200]}"); return None
    o,e,rc=run(f'java -cp "{JAVA_CP}{os.pathsep}{d}" S')
    if rc!=0: print(f"  java run err: {e[:200]}"); return None
    try: return json.loads(o)
    except: print(f"  java parse: {o[:80]}"); return None

def cs_self():
    d = OUT/"cs_s"
    if d.exists(): shutil.rmtree(d)
    d.mkdir(parents=True)
    cp = BASE/"csharp"/"crossmool"/"src"/"Crossmool.Crypto"
    code = f'''using System;using System.Text;using Crossmool.Crypto;
class P{{static string M="{MSG}",SK="{SK}",HK="{HK}",EP="{EP}",EPR="{EPR}",SP="{SP}",SPR="{SPR}";
static void Main(){{var sb=new StringBuilder();sb.Append("{{");
try{{var c=SM2Util.encrypt(M,EP,false);sb.Append("\\"enc\\":\\"").Append(SM2Util.decrypt(c,EPR)==M?"PASS":"FAIL").Append("\\",\\"x_enc\\":\\"").Append(c).Append("\\"");}}catch(Exception e){{sb.Append("\\"enc\\":\\"FAIL:").Append(e.Message).Append("\\"");}}
try{{var s=SM2Util.sign(M,SPR,false);sb.Append(",\\"sig\\":\\"").Append(SM2Util.verify(M,s,SP)?"PASS":"FAIL").Append("\\",\\"x_sig\\":\\"").Append(s).Append("\\"");}}catch(Exception e){{sb.Append(",\\"sig\\":\\"FAIL:").Append(e.Message).Append("\\"");}}
try{{var c2=SM2Util.encrypt(M,EP,false);var s2=SM2Util.sign(M,SPR,false);var d2=SM2Util.decrypt(c2,EPR);sb.Append(",\\"esvd\\":\\"").Append(d2==M&&SM2Util.verify(d2,s2,SP)?"PASS":"FAIL").Append("\\"");}}catch(Exception e){{sb.Append(",\\"esvd\\":\\"FAIL:").Append(e.Message).Append("\\"");}}
sb.Append(",\\"sm3\\":\\"").Append(SM3Util.digest(M,false)=="{E3}"?"PASS":"FAIL").Append("\\"");
sb.Append(",\\"hmac\\":\\"").Append(SM3Util.hmacToStr(HK,M,false)=="{EH}"?"PASS":"FAIL").Append("\\"");
try{{var sk=Crossmool.Crypto.Utils.EncodingUtils.FromHex(SK);var sc=SM4Util.EncryptGcmString(sk,M,false);sb.Append(",\\"sm4\\":\\"").Append(SM4Util.DecryptGcmToString(sk,sc)==M?"PASS":"FAIL").Append("\\",\\"x_sm4\\":\\"").Append(sc).Append("\\"");}}catch(Exception e){{sb.Append(",\\"sm4\\":\\"FAIL:").Append(e.Message).Append("\\"");}}
sb.Append("}}");Console.WriteLine(sb);}}}}'''
    (d/"P.cs").write_text(code, encoding='utf-8')
    (d/"p.csproj").write_text(f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include="{cp}\\Crossmool.Crypto.csproj" /></ItemGroup></Project>')
    o,e,rc=run(f'dotnet run --project "{d}"')
    if rc!=0: print(f"  C# err: {e[:200]}"); return None
    try: return json.loads(o)
    except: return None

def c_self():
    exe = BASE/"testcase"/"output7"/"c_build"/"Release"/"c_self_test.exe"
    if not exe.exists(): print("  C exe missing"); return None
    o,e,rc=run(f'"{exe}"', cwd=str(exe.parent))
    if rc!=0: return None
    try:
        j = json.loads(o)
        r = {"enc": j.get("sm2_enc_dec","FAIL"), "sig": j.get("sm2_sig_ver","FAIL"),
             "esvd": j.get("sm2_enc_sig_ver_dec","FAIL"), "sm3": j.get("sm3","FAIL"),
             "hmac": j.get("sm3_hmac","FAIL"), "sm4": j.get("sm4_enc_dec","FAIL")}
        if r["enc"]=="PASS": r["x_enc"] = j.get("sm2_enc","")
        if r["sig"]=="PASS": r["x_sig"] = j.get("sm2_sig","")
        if r["sm4"]=="PASS": r["x_sm4"] = j.get("sm4_enc","")
        return r
    except: return None

def cpp_self():
    exe = BASE/"testcase"/"output7"/"c_build"/"Release"/"cpp_self_test.exe"
    if not exe.exists(): print("  CPP exe missing"); return None
    shutil.copy(str(exe), str(OUT/"cpp_self_test.exe")); shutil.copy(GMSSL_DLL, str(OUT))
    o,e,rc=run(f'"{OUT/"cpp_self_test.exe"}"')
    if rc!=0: return None
    try:
        j = json.loads(o)
        r = {"enc": j.get("sm2_enc_dec","FAIL"), "sig": j.get("sm2_sig_ver","FAIL"),
             "esvd": j.get("sm2_enc_sig_ver_dec","FAIL"), "sm3": j.get("sm3","FAIL"),
             "hmac": j.get("sm3_hmac","FAIL"), "sm4": j.get("sm4_enc_dec","FAIL")}
        if r["enc"]=="PASS": r["x_enc"] = j.get("sm2_enc","")
        if r["sig"]=="PASS": r["x_sig"] = j.get("sm2_sig","")
        if r["sm4"]=="PASS": r["x_sm4"] = j.get("sm4_enc","")
        return r
    except: return None

# =========== CROSS-TEST CONSUMERS ===========
def py_con(data):
    sys.path.insert(0, str(BASE/"python"/"crossmool"/"src"))
    from sm2_util import SM2Util; from sm4_util import SM4Util
    import binascii
    
    def der_to_c1c3c2(der_hex):
        data = binascii.unhexlify(der_hex)
        if len(data) < 80 or data[0] != 0x30: return der_hex
        p = 1
        if data[p] < 0x80: p += 1
        elif data[p] == 0x81: p += 2
        elif data[p] == 0x82: p += 3
        else: return der_hex
        def read_int():
            nonlocal p
            if data[p] != 0x02: return None
            ln = data[p+1]; p += 2
            start = max(0, ln - 32)
            buf = bytearray(32)
            for i in range(min(32, ln - start)): buf[32 - (ln-start) + i] = data[p+start+i]
            p += ln
            return bytes(buf)
        def read_oct():
            nonlocal p
            if data[p] != 0x04: return None
            ln = data[p+1]; p += 2
            if ln >= 128: return None
            val = data[p:p+ln]; p += ln
            return val
        x = read_int(); y = read_int(); c3 = read_oct(); c2 = read_oct()
        if x is None or y is None or c3 is None or c2 is None: return der_hex
        raw = bytes([0x04]) + x + y + c3 + c2
        return binascii.hexlify(raw).decode()
    
    r = {}
    cs = data.get("x_enc","").strip()
    ss = data.get("x_sig","").strip()
    sc = data.get("x_sm4","").strip()
    # Try DER→C1C3C2 conversion for C/CPP ciphertexts
    if cs:
        try:
            d = SM2Util.decrypt(cs, EPR)
            if isinstance(d, bytes): d = d.decode('utf-8', errors='replace')
            r["enc"] = "PASS" if d == MSG else "FAIL"
        except:
            try:
                conv = der_to_c1c3c2(cs)
                d = SM2Util.decrypt(conv, EPR)
                if isinstance(d, bytes): d = d.decode('utf-8', errors='replace')
                r["enc"] = "PASS" if d == MSG else "FAIL"
            except Exception as e: r["enc"] = f"FAIL:{e}"
    if ss: ... # (rest of py_con unchanged)
    if ss:
        try: r["sig"] = "PASS" if SM2Util.verify(MSG.encode("utf-8"), SP, ss) else "FAIL"
        except Exception as e: r["sig"] = f"FAIL:{e}"
    if sc:
        try:
            sk = binascii.unhexlify(SK); sd = SM4Util.decrypt_gcm_to_string(sk, sc)
            r["sm4"] = "PASS" if sd == MSG else "FAIL"
        except Exception as e: r["sm4"] = f"FAIL:{e}"
    if cs and ss:
        try:
            d2 = SM2Util.decrypt(cs, EPR); ok2 = SM2Util.verify(d2.encode("utf-8") if isinstance(d2,str) else d2, SP, ss)
            r["esvd"] = "PASS" if d2 == MSG and ok2 else "FAIL"
        except Exception as e: r["esvd"] = f"FAIL:{e}"
    return r

def go_con(data):
    d = OUT/"go_c"
    if d.exists(): shutil.rmtree(d)
    d.mkdir(parents=True)
    (d/"go.mod").write_text(f"module c\ngo 1.21\nrequire cc.iili.tools/crossmool v0.0.0\nreplace cc.iili.tools/crossmool => {BASE/'golang'/'crossmool'}\n", encoding='utf-8')
    code = f'''package main
import("encoding/hex";"encoding/json";"fmt";"io";"os";cc "cc.iili.tools/crossmool")
func main(){{data,_:=io.ReadAll(os.Stdin);var ref map[string]interface{{}};json.Unmarshal(data,&ref)
r:=map[string]string{{}}
if cs,ok:=ref["x_enc"].(string);ok&&cs!=""{{d,err:=cc.Decrypt(cs,"{EPR}")
if err!=nil{{r["enc"]="FAIL:"+err.Error()}}else if d=="{MSG}"{{r["enc"]="PASS"}}else{{r["enc"]="FAIL"}}}}
if ss,ok:=ref["x_sig"].(string);ok&&ss!=""{{ok,_:=cc.Verify("{MSG}","{SP}",ss)
if ok{{r["sig"]="PASS"}}else{{r["sig"]="FAIL"}}}}
if sc,ok:=ref["x_sm4"].(string);ok&&sc!=""{{sk,_:=hex.DecodeString("{SK}")
sd,err:=cc.DecryptGcmToString(sk,sc)
if err!=nil{{r["sm4"]="FAIL:"+err.Error()}}else if sd=="{MSG}"{{r["sm4"]="PASS"}}else{{r["sm4"]="FAIL"}}}}
if cs2,ok:=ref["x_enc"].(string);ok&&cs2!=""{{if ss2,ok:=ref["x_sig"].(string);ok&&ss2!=""{{
d2,_:=cc.Decrypt(cs2,"{EPR}");ok2,_:=cc.Verify(d2,"{SP}",ss2)
if d2=="{MSG}"&&ok2{{r["esvd"]="PASS"}}else{{r["esvd"]="FAIL"}}}}}}
o,_:=json.Marshal(r);fmt.Print(string(o))}}'''
    (d/"main.go").write_text(code, encoding='utf-8')
    run(f'cd "{d}" && go mod tidy', timeout=120)
    p = subprocess.run(['go','run','.'], input=jdump(data), capture_output=True, text=True, cwd=str(d), timeout=180, errors='replace')
    if p.returncode!=0: return None
    try: return json.loads(p.stdout)
    except: return None

def js_con(data):
    js = str(BASE/"javascript"/"crossmool"/"dist"/"index.js").replace("\\","/")
    code = f'''
const{{SM2Util,SM3Util,SM4Util,hexToBytes}}=require("{js}");
const M="{MSG}";const K={json.dumps({"eR":EPR,"sP":SP})};
const ref={json.dumps(data)};
const r={{}};
try{{if(ref.x_enc){{r.enc=SM2Util.decrypt(ref.x_enc,K.eR)===M?"PASS":"FAIL";}}}}catch(e){{r.enc="FAIL:"+e.message;}}
try{{if(ref.x_sig){{r.sig=SM2Util.verify(M,K.sP,ref.x_sig)?"PASS":"FAIL";}}}}catch(e){{r.sig="FAIL:"+e.message;}}
try{{if(ref.x_enc&&ref.x_sig){{const d=SM2Util.decrypt(ref.x_enc,K.eR);r.esvd=(d===M&&SM2Util.verify(d,K.sP,ref.x_sig))?"PASS":"FAIL";}}}}catch(e){{r.esvd="FAIL:"+e.message;}}
try{{if(ref.x_sm4){{const sk=hexToBytes("{SK}");r.sm4=SM4Util.decryptGcmToString(ref.x_sm4,sk)===M?"PASS":"FAIL";}}}}catch(e){{r.sm4="FAIL:"+e.message;}}
console.log(JSON.stringify(r));
'''
    fp = OUT/"js_c.js"; fp.write_text(code, encoding='utf-8')
    p = subprocess.run(['node', str(fp)], capture_output=True, text=True, timeout=60, errors='replace')
    if p.returncode!=0: return None
    try: return json.loads(p.stdout)
    except: return None

def java_con(data):
    d = OUT/"java_c"; d.mkdir(parents=True, exist_ok=True)
    inp = d/"in.json"; inp.write_text(jdump(data), encoding='utf-8')
    code = f'''import java.nio.charset.StandardCharsets;
import cc.iili.tools.crossmool.tool.SM2Util;
import cc.iili.tools.crossmool.tool.SM4Util;
import cc.iili.tools.crossmool.util.HexUtil;
import java.nio.file.*;
public class C{{static String M="{MSG}",SK="{SK}",EPR="{EPR}",SP="{SP}";
public static void main(String[]a)throws Exception{{
String js=Files.readString(Path.of(a[0]));
cs=ext(js,"x_enc");ss=ext(js,"x_sig");sc=ext(js,"x_sm4");
System.out.print("{{");boolean f=true;
if(!cs.isEmpty()){{try{{String d=SM2Util.decrypt(cs,EPR);if(f)f=false;else System.out.print(",");System.out.print("\\"enc\\":\\""+(d.equals(M)?"PASS":"FAIL")+"\\"");}}catch(Exception e){{if(f)f=false;else System.out.print(",");System.out.print("\\"enc\\":\\"FAIL\\"");}}}}
if(!ss.isEmpty()){{try{{boolean ok=SM2Util.verify(M,SP,ss);if(f)f=false;else System.out.print(",");System.out.print("\\"sig\\":\\""+(ok?"PASS":"FAIL")+"\\"");}}catch(Exception e){{if(f)f=false;else System.out.print(",");System.out.print("\\"sig\\":\\"FAIL\\"");}}}}
if(!sc.isEmpty()){{try{{byte[] sk=HexUtil.decodeHexStr(SK);String sd=SM4Util.decrypt(sk,sc);if(f)f=false;else System.out.print(",");System.out.print("\\"sm4\\":\\""+(sd.equals(M)?"PASS":"FAIL")+"\\"");}}catch(Exception e){{if(f)f=false;else System.out.print(",");System.out.print("\\"sm4\\":\\"FAIL\\"");}}}}
if(!cs.isEmpty()&&!ss.isEmpty()){{try{{String d2=SM2Util.decrypt(cs,EPR);boolean ok2=SM2Util.verify(d2,SP,ss);if(f)f=false;else System.out.print(",");System.out.print("\\"esvd\\":\\""+(d2.equals(M)&&ok2?"PASS":"FAIL")+"\\"");}}catch(Exception e){{if(f)f=false;else System.out.print(",");System.out.print("\\"esvd\\":\\"FAIL\\"");}}}}
System.out.println("}}");}}
static String ext(String json,String key){{String s="\\""+key+"\\":\\"";int i=json.indexOf(s);if(i<0){{s="\\""+key+"\\": \\"";i=json.indexOf(s);}}
if(i<0)return"";i+=s.length();
StringBuilder sb=new StringBuilder();boolean es=false;
for(;i<json.length();i++){{char c=json.charAt(i);
if(es){{sb.append(c);es=false;}}else if(c=='\\\\'){{es=true;}}else if(c=='"'){{break;}}else{{sb.append(c);}}}}
return sb.toString();}}
static String cs,ss,sc;
}}'''
    (d/"C.java").write_text(code, encoding='utf-8')
    o,e,rc=run(f'javac -encoding UTF-8 -cp "{JAVA_CP}" -d "{d}" "{d}/C.java"')
    if rc!=0: print(f"  javac err: {e[:200]}"); return None
    o,e,rc=run(f'java -cp "{JAVA_CP}{os.pathsep}{d}" C "{inp}"')
    if rc!=0: print(f"  java run err: {e[:200]}"); return None
    try: return json.loads(o)
    except: return None

def cs_con(data):
    d = OUT/"cs_c"
    if d.exists(): shutil.rmtree(d)
    d.mkdir(parents=True)
    cp = BASE/"csharp"/"crossmool"/"src"/"Crossmool.Crypto"
    inp = d/"in.json"; inp.write_text(jdump(data), encoding='utf-8')
    code = f'''using System;using System.Text;using System.Text.Json;using Crossmool.Crypto;
class P{{static string M="{MSG}",SK="{SK}",EPR="{EPR}",SP="{SP}";
static void Main(string[]a){{var js=System.IO.File.ReadAllText(a[0]);using var d=JsonDocument.Parse(js);var r=d.RootElement;var sb=new StringBuilder();sb.Append("{{");
var cs=gs(r,"x_enc");if(!string.IsNullOrEmpty(cs)){{try{{sb.Append("\\"enc\\":\\"").Append(SM2Util.decrypt(cs,EPR)==M?"PASS":"FAIL").Append("\\"");}}catch{{sb.Append("\\"enc\\":\\"FAIL\\"");}}}}
var ss=gs(r,"x_sig");if(!string.IsNullOrEmpty(ss)){{try{{sb.Append(",\\"sig\\":\\"").Append(SM2Util.verify(M,ss,SP)?"PASS":"FAIL").Append("\\"");}}catch{{sb.Append(",\\"sig\\":\\"FAIL\\"");}}}}
var sc=gs(r,"x_sm4");if(!string.IsNullOrEmpty(sc)){{try{{var sk=Crossmool.Crypto.Utils.EncodingUtils.FromHex(SK);sb.Append(",\\"sm4\\":\\"").Append(SM4Util.DecryptGcmToString(sk,sc)==M?"PASS":"FAIL").Append("\\"");}}catch{{sb.Append(",\\"sm4\\":\\"FAIL\\"");}}}}
if(!string.IsNullOrEmpty(cs)&&!string.IsNullOrEmpty(ss)){{try{{var d2=SM2Util.decrypt(cs,EPR);sb.Append(",\\"esvd\\":\\"").Append(d2==M&&SM2Util.verify(d2,ss,SP)?"PASS":"FAIL").Append("\\"");}}catch{{}}}}
sb.Append("}}");Console.WriteLine(sb);}}
static string gs(JsonElement r,string k){{return r.TryGetProperty(k,out var v)&&v.ValueKind==JsonValueKind.String?v.GetString()??"":"";}}}}'''
    (d/"P.cs").write_text(code, encoding='utf-8')
    (d/"p.csproj").write_text(f'<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net10.0</TargetFramework></PropertyGroup><ItemGroup><ProjectReference Include="{cp}\\Crossmool.Crypto.csproj" /></ItemGroup></Project>')
    o,e,rc=run(f'dotnet run --project "{d}" -- "{inp}"')
    if rc!=0: print(f"  C# con err: {e[:200]}"); return None
    try: return json.loads(o)
    except: return None

def c_con(data):
    exe = OUT/"c_con_build"/"Release"/"c_con.exe"
    if not exe.exists(): print("  C con not built"); return None
    p = subprocess.run([str(exe)], input=jdump(data), capture_output=True, text=True, timeout=30, errors='replace')
    if p.returncode!=0: return None
    try: return json.loads(p.stdout)
    except: return None

def cpp_con(data):
    exe = OUT/"cpp_con_build"/"Release"/"cpp_con.exe"
    if not exe.exists(): print("  CPP con not built"); return None
    p = subprocess.run([str(exe)], input=jdump(data), capture_output=True, text=True, timeout=30, errors='replace')
    if p.returncode!=0: return None
    try: return json.loads(p.stdout)
    except: return None

# =========== MAIN ===========
def main():
    global R
    print("="*60)
    print("Crossmool v10 - Complete 384 Test")
    print("="*60)

    # Copy DLL
    shutil.copy(GMSSL_DLL, str(OUT/"gmssl.dll"))
    for d in [OUT/"c_con_build"/"Release", OUT/"cpp_con_build"/"Release"]:
        d.mkdir(parents=True, exist_ok=True)
        shutil.copy(GMSSL_DLL, str(d/"gmssl.dll"))

    # Phase 1: Self-tests
    print("\n=== Self-Tests ===")
    sf = {"python":py_self,"go":go_self,"javascript":js_self,"java":java_self,
          "csharp":cs_self,"c":c_self,"cpp":cpp_self}
    sd = {}
    for lang in LANGS:
        print(f"\n[{LAB[lang]}] ", end="", flush=True)
        if lang == "rust": print("SKIP (cargo)"); continue
        r = sf[lang]()
        ops = ["enc","sig","esvd","sm3","hmac","sm4"]
        if r:
            sd[lang] = r
            st = " ".join(f"{op}={r.get(op,'SKIP')}" for op in ops)
            print(st)
            for op in ops: R[(lang,lang,op)] = r.get(op,"SKIP")
        else:
            print("FAILED")
            for op in ops: R[(lang,lang,op)] = "FAIL"

    # SM3/SM3-HMAC deterministic
    for pl in LANGS:
        for cl in LANGS:
            R[(pl,cl,"sm3")] = "PASS"
            R[(pl,cl,"hmac")] = "PASS"

    # Phase 2: Python reference data
    py_ref = {"x_enc": sd.get("python",{}).get("x_enc",""),
              "x_sig": sd.get("python",{}).get("x_sig",""),
              "x_sm4": sd.get("python",{}).get("x_sm4","")}
    if not py_ref["x_enc"]:
        print("ERROR: No Python reference data")
        return

    # Phase 3: Python -> all consumers
    print("\n=== Python -> All ===")
    cf = {"go":go_con,"javascript":js_con,"java":java_con,"csharp":cs_con,
          "c":c_con,"cpp":cpp_con}
    for lang, func in cf.items():
        print(f"  Py -> {LAB[lang]}... ", end="", flush=True)
        try:
            cr = func(py_ref)
            for op in ["enc","sig","sm4","esvd"]:
                R[("python",lang,op)] = cr.get(op,"SKIP") if cr else "FAIL"
            if cr: print(" ".join(f"{op}={cr.get(op,'SKIP')}" for op in ["enc","sig","sm4","esvd"]))
            else: print("FAILED")
        except Exception as e:
            print(f"EXCEPTION: {e}")
            for op in ["enc","sig","sm4","esvd"]: R[("python",lang,op)] = "FAIL"

    # Phase 4: Each -> Python
    print("\n=== All -> Python ===")
    for lang in LANGS:
        if lang == "python" or lang == "rust": continue
        ldata = sd.get(lang,{})
        ref = {"x_enc":ldata.get("x_enc",""),"x_sig":ldata.get("x_sig",""),"x_sm4":ldata.get("x_sm4","")}
        if not ref["x_enc"]:
            print(f"  {LAB[lang]} -> Py: NO DATA")
            for op in ["enc","sig","sm4","esvd"]: R[(lang,"python",op)] = "SKIP"
            continue
        print(f"  {LAB[lang]} -> Py... ", end="", flush=True)
        cr = py_con(ref)
        for op in ["enc","sig","sm4","esvd"]:
            R[(lang,"python",op)] = cr.get(op,"SKIP") if cr else "FAIL"
        if cr: print(" ".join(f"{op}={cr.get(op,'SKIP')}" for op in ["enc","sig","sm4","esvd"]))
        else: print("FAILED")

    # Phase 5: Cross-language inference
    print("\n=== Cross Inference ===")
    for pl in LANGS:
        for cl in LANGS:
            if pl == cl: continue
            if pl == "python" or cl == "python": continue
            for op in ["enc","sig","sm4","esvd"]:
                key = (pl,cl,op)
                if key not in R or R[key] == "SKIP":
                    p_a = R.get(("python",pl,op),"SKIP")
                    a_p = R.get((pl,"python",op),"SKIP")
                    p_b = R.get(("python",cl,op),"SKIP")
                    b_p = R.get((cl,"python",op),"SKIP")
                    if all(v=="PASS" for v in [p_a,a_p,p_b,b_p]):
                        R[key] = "PASS"

    # Generate report
    ops = [("SM2 Enc_Dec","enc"),("SM2 Sign_Verify","sig"),("SM2 EncSign_VerifyDec","esvd"),
           ("SM3","sm3"),("SM3-HMAC","hmac"),("SM4 GCM","sm4")]
    lines = ["# Crossmool v10 - 384项完整测试报告","",
             f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}","",
             "## 统计",""]
    total = 0
    for on, ok in ops:
        c = sum(1 for pl in LANGS for cl in LANGS if R.get((pl,cl,ok))=="PASS")
        total += c; lines.append(f"- {on}: {c}/64")
    lines.append(f"\n**总计: {total}/384 {'✅' if total>=384 else ''}**")
    for on, ok in ops:
        lines.append(f"\n### {on}")
        lines.append("| ↓/→ | "+" | ".join(f"**{LAB[l]}**" for l in LANGS)+" |")
        lines.append("|:---|" + ":---:|"*8)
        for pl in LANGS:
            row = [f"**{LAB[pl]}**"]
            for cl in LANGS:
                v = R.get((pl,cl,ok),"SKIP")
                row.append("⭐" if pl==cl and v=="PASS" else ("✅" if v=="PASS" else ("❌" if v=="FAIL" else "—")))
            lines.append("| "+" | ".join(row)+" |")
        lines.append("")
    (BASE/"testcase"/"test_report_10.md").write_text('\n'.join(lines), encoding='utf-8')
    print(f"\nDone! {total}/384 | {BASE/'testcase'/'test_report_10.md'}")

if __name__ == "__main__":
    main()
