#!/usr/bin/env python3
"""SM2 Full Cross-Language Interoperability Test — Driver Script"""
import sys, json, subprocess, os

sys.path.insert(0, 'G:/workspaces/git/corssmool/crossmool/python/crossmool/src')
from sm2_util import SM2Util
from encoding import utf8_to_bytes

PLAIN1 = "Hello, 你好，我是张三丰，你是誰啊，來自哪裡？"
PLAIN2 = '今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。路过咖啡店时買了一杯美式，順便（顺便）看了下手机，今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。朋友发来一条消息说："Don\'t forget to bring your umbrella, just in case!" 我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。'

# Generate keys
enc_kp = SM2Util.generate_keypair_hex()
sig_kp = SM2Util.generate_keypair_hex()

# Encrypt + EncryptSign
ct1_hex = SM2Util.encrypt(PLAIN1, enc_kp['publicKey'])
ct1_b64 = SM2Util.encrypt(PLAIN1, enc_kp['publicKey'], to_base64=True)
pair_hex = SM2Util.encrypt_sign(PLAIN2, enc_kp['publicKey'], sig_kp['privateKey'], to_base64=False)
pair_b64 = SM2Util.encrypt_sign(PLAIN2, enc_kp['publicKey'], sig_kp['privateKey'], to_base64=True)

tv = {
    'enc_pub_hex': enc_kp['publicKey'], 'enc_priv_hex': enc_kp['privateKey'],
    'sig_pub_hex': sig_kp['publicKey'], 'sig_priv_hex': sig_kp['privateKey'],
    'plain1': PLAIN1, 'plain2': PLAIN2,
    'ct1_hex': ct1_hex, 'ct1_b64': ct1_b64,
    'ct2_hex': pair_hex['ciphertext'], 'sig2_hex': pair_hex['signature'],
    'ct2_b64': pair_b64['ciphertext'], 'sig2_b64': pair_b64['signature']
}
with open('G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json', 'w', encoding='utf-8') as f:
    json.dump(tv, f, ensure_ascii=False, indent=2)

def run_test(name, lang, lang_code):
    """Run test in a specific language"""
    if lang == 'python':
        sys.path.insert(0, 'G:/workspaces/git/corssmool/crossmool/python/crossmool/src')
        from sm2_util import SM2Util as P
    elif lang == 'javascript':
        pass  # handled separately
    # ... (simplified for now)
    
    results = {}
    for direction in ['hex', 'b64']:
        ct = tv['ct1_hex'] if direction == 'hex' else tv['ct1_b64']
        ct2 = tv['ct2_hex'] if direction == 'hex' else tv['ct2_b64']
        sig2 = tv['sig2_hex'] if direction == 'hex' else tv['sig2_b64']
        
        try:
            # Encrypt
            if lang == 'python':
                my_ct = P.encrypt(tv['plain1'], tv['enc_pub_hex'], to_base64=(direction=='b64'))
                results[f'enc_{direction}'] = len(my_ct) > 0
                dec = P.decrypt(ct, tv['enc_priv_hex'])
                results[f'dec_{direction}'] = dec == tv['plain1']
                pair = P.encrypt_sign(tv['plain2'], tv['enc_pub_hex'], tv['sig_priv_hex'], to_base64=(direction=='b64'))
                results[f'enc_sign_{direction}'] = len(pair['ciphertext']) > 0
                vd = P.verify_decrypt(ct2, sig2, tv['sig_pub_hex'], tv['enc_priv_hex'])
                results[f'vd_{direction}'] = vd == tv['plain2']
        except Exception as e:
            results[f'error'] = str(e)
    
    print(f"  {name}: ", end='')
    if 'error' in results:
        print(f"ERROR - {results['error']}")
        return {'error': str(results['error'])}
    ok = all(v for k, v in results.items() if not k.startswith('error'))
    print("OK" if ok else f"FAILED: {[k for k,v in results.items() if not v]}")
    return results

# Run Python
print("=== Python ===")
py_r = run_test('Python', 'python', 'python')

# Run JS
print("=== JavaScript ===")
js_script = f'''
const {{ SM2Util }} = require('./dist/index.js');
const tv = {json.dumps(tv, ensure_ascii=False)};
const r = {{}};
function test(name, fn) {{ try {{ r[name] = fn(); }} catch(e) {{ r[name+'!'] = e.message; }} }}
test('enc_hex', () => SM2Util.encrypt(tv.plain1, tv.enc_pub_hex).length > 0);
test('enc_b64', () => SM2Util.encrypt(tv.plain1, tv.enc_pub_hex, true).length > 0);
test('dec_hex', () => SM2Util.decrypt(tv.ct1_hex, tv.enc_priv_hex) === tv.plain1);
test('dec_b64', () => SM2Util.decrypt(tv.ct1_b64, tv.enc_priv_hex) === tv.plain1);
test('enc_sign_hex', () => {{ let p = SM2Util.encryptSign(tv.plain2, tv.enc_pub_hex, tv.sig_priv_hex, false); return p.ciphertext.length > 0; }});
test('enc_sign_b64', () => {{ let p = SM2Util.encryptSign(tv.plain2, tv.enc_pub_hex, tv.sig_priv_hex, true); return p.ciphertext.length > 0; }});
test('vd_hex', () => SM2Util.verifyDecrypt(tv.ct2_hex, tv.sig2_hex, tv.sig_pub_hex, tv.enc_priv_hex) === tv.plain2);
test('vd_b64', () => SM2Util.verifyDecrypt(tv.ct2_b64, tv.sig2_b64, tv.sig_pub_hex, tv.enc_priv_hex) === tv.plain2);
console.log(JSON.stringify(r));
'''
with open('G:/workspaces/git/corssmool/crossmool/userdoc/js_test_temp.js', 'w', encoding='utf-8') as f:
    f.write(js_script)
try:
    out = subprocess.run(['node', '-e', js_script], capture_output=True, text=True, timeout=60,
                         cwd='G:/workspaces/git/corssmool/crossmool/javascript/crossmool')
    js_r = json.loads(out.stdout.strip())
    errs = [k for k,v in js_r.items() if v is not True and not k.endswith('!')]
    if errs or any(k.endswith('!') for k in js_r):
        print(f"  JS: FAILED: {js_r}")
    else:
        print("  JS: OK")
except Exception as e:
    js_r = {'error': str(e)}
    print(f"  JS: ERROR - {e}")

print("\n=== Cross-language Summary ===")
print(f"  Python: {'OK' if 'error' not in py_r else py_r['error']}")
print(f"  JS:     {'OK' if 'error' not in js_r else js_r['error']}")
print(f"\nTest vectors: userdoc/test_vectors.json")
