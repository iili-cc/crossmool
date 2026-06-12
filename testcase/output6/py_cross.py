import json, sys, os, binascii
sys.path.insert(0, r"G:\workspaces\git\corssmool\crossmool\python\crossmool\src")
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
DK = {"enc_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "enc_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sig_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sig_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"}
SM4_KEY = binascii.unhexlify("0123456789abcdeffedcba9876543210")
HMAC_KEY = binascii.unhexlify("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
ref = json.loads(sys.stdin.read())
MSG = ref.get("msg", """Hello, 这是跨语言国密互通性测试数据""")
r = {"lang":"python","consumer_of":ref.get("lang","unknown")}

cs = ref.get("sm2_enc","")
if cs:
    try:
        d = SM2Util.decrypt(cs, DK["enc_priv_der_hex"])
        r["sm2_dec"] = "PASS" if d == MSG else "FAIL"
    except Exception as e: r["sm2_dec"] = f"FAIL: {e}"
else: r["sm2_dec"] = "SKIP"

ss = ref.get("sm2_sig","")
if ss:
    try:
        ok = SM2Util.verify(MSG.encode("utf-8"), DK["sig_pub_der_hex"], ss)
        r["sm2_ver"] = "PASS" if ok else "FAIL"
    except Exception as e: r["sm2_ver"] = f"FAIL: {e}"
else: r["sm2_ver"] = "SKIP"

sc = ref.get("sm4_enc","")
if sc:
    try:
        sd = SM4Util.decrypt_gcm_to_string(SM4_KEY, sc)
        r["sm4_dec"] = "PASS" if sd == MSG else "FAIL"
    except Exception as e: r["sm4_dec"] = f"FAIL: {e}"
else: r["sm4_dec"] = "SKIP"

sh = ref.get("sm3_hash","")
if sh:
    try:
        h = SM3Util.digest_str(MSG, to_base64=False)
        r["sm3"] = "PASS" if h == sh else "FAIL"
    except Exception as e: r["sm3"] = f"FAIL: {e}"

hh = ref.get("sm3_hmac_hash","")
if hh:
    try:
        hm = SM3Util.hmac_to_hex(HMAC_KEY, MSG.encode("utf-8"))
        r["sm3_hmac"] = "PASS" if hm == hh else "FAIL"
    except Exception as e: r["sm3_hmac"] = f"FAIL: {e}"

print(json.dumps(r, ensure_ascii=False))