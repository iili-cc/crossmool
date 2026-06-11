
import sys, json
sys.path.insert(0, r"D:/workspaces/git/corssmool/crossmool\python\crossmool\src")
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
from encoding import hex_to_bytes, utf8_to_bytes
D = {"msg": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e", "enc_priv": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", "enc_pub": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sig_priv": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3", "sig_pub": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sm4_key": "0123456789abcdeffedcba9876543210", "hmac_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}
MSG = D["msg"]
r = {}
# SM2 Enc/Dec
c = SM2Util.encrypt(MSG, D["enc_pub"])
r["sm2_enc"] = c
d = SM2Util.decrypt(c, D["enc_priv"])
r["sm2_enc_dec"] = "PASS" if d == MSG else "FAIL"
# SM2 Sig/Ver
s = SM2Util.sign(MSG, D["sig_priv"])
r["sm2_sig"] = s
ok = SM2Util.verify_str(MSG, D["sig_pub"], s)
r["sm2_sig_ver"] = "PASS" if ok else "FAIL"
# SM3
dig = SM3Util.digest_str(MSG, False)
r["sm3_hash"] = dig
# SM3-HMAC
hmac = SM3Util.hmac_str(D["hmac_key"], MSG, False)
r["sm3_hmac_hash"] = hmac
# SM4
sk = hex_to_bytes(D["sm4_key"])
sc = SM4Util.encrypt_gcm(sk, utf8_to_bytes(MSG))
r["sm4_enc"] = sc
sd = SM4Util.decrypt_gcm_to_string(sk, sc)
r["sm4_enc_dec"] = "PASS" if sd == MSG else "FAIL"
# Cross verify data for other languages
r["cross"] = {
    "sm2_enc": r["sm2_enc"],
    "sm2_sig": r["sm2_sig"],
    "sm4_enc": r["sm4_enc"],
    "sm3_hash": r["sm3_hash"],
    "sm3_hmac_hash": r["sm3_hmac_hash"],
}
print(json.dumps(r, ensure_ascii=False))
