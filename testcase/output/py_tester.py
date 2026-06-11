
import sys, json
sys.path.insert(0, r"D:/workspaces/git/corssmool/crossmool\python\crossmool\src")
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
from encoding import hex_to_bytes, utf8_to_bytes

D = {"msg": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e", "sm2_enc_priv": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", "sm2_enc_pub": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sm2_sig_priv": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3", "sm2_sig_pub": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sm4_key": "0123456789abcdeffedcba9876543210", "sm4_iv": "000102030405060708090a0b", "hmac_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}
EXP = {"sm3": "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b", "sm3_hmac": "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"}
MSG = D["msg"]

r = {}
# SM3
d = SM3Util.digest_str(MSG, False)
r["sm3"] = d
r["sm3_ok"] = (d == EXP["sm3"])

# SM3-HMAC  
h = SM3Util.hmac_str(D["hmac_key"], MSG, False)
r["sm3_hmac"] = h
r["sm3_hmac_ok"] = (h == EXP["sm3_hmac"])

# Generate own SM2/SM4
r["sm2_enc"] = SM2Util.encrypt(MSG, D["sm2_enc_pub"], False)
r["sm2_sig"] = SM2Util.sign(MSG, D["sm2_sig_priv"], False)
sm4_key = hex_to_bytes(D["sm4_key"])
r["sm4_enc"] = SM4Util.encrypt_gcm(sm4_key, utf8_to_bytes(MSG), to_base64=False)

# Verify reference vectors (passed via stdin or file)
import_file = sys.argv[1] if len(sys.argv) > 1 else None
if import_file:
    with open(import_file, 'r', encoding='utf-8') as f:
        ref = json.load(f)
    try:
        dec = SM2Util.decrypt(ref["sm2_enc"], D["sm2_enc_priv"])
        r["sm2_dec_ok"] = (dec == MSG)
    except Exception as e:
        r["sm2_dec_ok"] = False; r["sm2_dec_err"] = str(e)
    try:
        ok = SM2Util.verify_str(MSG, D["sm2_sig_pub"], ref["sm2_sig"])
        r["sm2_ver_ok"] = ok
    except Exception as e:
        r["sm2_ver_ok"] = False; r["sm2_ver_err"] = str(e)
    try:
        es = ref.get("sm2_enc_sign", {})
        ok = SM2Util.verify_str(es.get("cipher",""), D["sm2_sig_pub"], es.get("sig",""))
        dec = SM2Util.decrypt(es.get("cipher",""), D["sm2_enc_priv"]) if ok else None
        r["sm2_esvd_ok"] = (ok and dec == MSG)
    except Exception as e:
        r["sm2_esvd_ok"] = False; r["sm2_esvd_err"] = str(e)
    try:
        sm4k = hex_to_bytes(D["sm4_key"])
        dec = SM4Util.decrypt_gcm_to_string(sm4k, ref["sm4_enc"])
        r["sm4_dec_ok"] = (dec == MSG)
    except Exception as e:
        r["sm4_dec_ok"] = False; r["sm4_dec_err"] = str(e)

print(json.dumps(r, ensure_ascii=False))
