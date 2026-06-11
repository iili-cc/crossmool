
import sys, json
sys.path.insert(0, r"D:/workspaces/git/corssmool/crossmool\python\crossmool\src")
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
from encoding import bytes_to_hex, utf8_to_bytes, hex_to_bytes

D = {"msg": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e", "sm2_enc_priv": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", "sm2_enc_pub": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sm2_sig_priv": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3", "sm2_sig_pub": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sm4_key": "0123456789abcdeffedcba9876543210", "sm4_iv": "000102030405060708090a0b", "hmac_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"}
MSG = D["msg"]

r = {}

# SM2 encrypt
r["sm2_enc"] = SM2Util.encrypt(MSG, D["sm2_enc_pub"], False)

# SM2 sign
r["sm2_sig"] = SM2Util.sign(MSG, D["sm2_sig_priv"], False)

# SM2 encryptSign
r["sm2_enc_sign"] = {"cipher": r["sm2_enc"], "sig": SM2Util.sign(r["sm2_enc"], D["sm2_sig_priv"], False)}

# SM4 encrypt (use fixed IV for determinism)
from gmssl import sm4
sm4_key = hex_to_bytes(D["sm4_key"])
sm4_iv = hex_to_bytes(D["sm4_iv"])
# sm4_util.SM4Util has encrypt_gcm
r["sm4_enc"] = SM4Util.encrypt_gcm(sm4_key, utf8_to_bytes(MSG), to_base64=False)

print(json.dumps(r, ensure_ascii=False))
