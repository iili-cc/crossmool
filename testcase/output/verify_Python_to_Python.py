
import sys, os, json
sys.path.insert(0, os.path.join(r"D:\workspaces\git\corssmool\crossmool", "python", "crossmool", "src"))
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
from encoding import hex_to_bytes, utf8_to_bytes, bytes_to_hex

KEYS = {
  "sm2_enc_priv_raw": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03",
  "sm2_enc_pub_raw": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356",
  "sm2_sign_priv_raw": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3",
  "sm2_sign_pub_raw": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226",
  "sm4_key": "0123456789abcdeffedcba9876543210",
  "sm4_iv": "000102030405060708090a0b",
  "sm3_hmac_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "test_msg": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e",
  "sm2_user_id": "1234567812345678"
}
MSG = KEYS["test_msg"]

CONSUMER_DATA = {
  "sm2_encrypt": {
    "cipher_hex": "1e138b46af86e6a5263f28624e3f1c183f906c8261af367978298042d4b653fe79388b8122d66272fb920f77fb9a1637d9ef862453bca6760b55f38687c3d94f1b49899dc56d188ab46fd46d063d85e14b52f3cbed0e9e96813c768acd432a9aad7a706a9b11b1e81fc8388b47e2427a8b83da7e40eabe9d6184b4db940bf24e15176fb08b5907349b056d91c1810987a4",
    "cipher_b64": "vl53AlbtymAGaVb+PRUQhVnvM9XihWJv0mkjnEkptFI3zFfAJZK9XI4Mzu4vrgaTOGf0qE9FkpeMj4WAMHsi7JFYdNHA36hA/J6cpfqhDIzZ1/YohLX+D/417zGSXoIsLPqWVyEGUDLAFwU5JUqtqrG5tP3dpTA875JPJR1gE4qgfCPkRgC2xdWSlDJjSgo6cQ=="
  },
  "sm2_decrypt": {
    "plaintext": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e",
    "status": "OK"
  },
  "sm2_sign": {
    "signature_hex": "3045022100f670573bd02546f3462c3da002b67f3249a441ae6c481ea0843af93c727bb5050220649c661b820832d5b1d580d81fbf59db95dd841a58bcaf9b85c7b57d227c2cf2",
    "signature_b64": "MEYCIQCbWpzJY7Xfs5O46IPG0BwmwyBckE5ZjTgFFepsFXL0OwIhAKZordzh7/aG2GJLicz6fAMRjX70FiV530VItcd7EG6/"
  },
  "sm2_verify": {
    "verified": true,
    "status": "OK"
  },
  "sm2_encrypt_sign": {
    "cipher_hex": "1e138b46af86e6a5263f28624e3f1c183f906c8261af367978298042d4b653fe79388b8122d66272fb920f77fb9a1637d9ef862453bca6760b55f38687c3d94f1b49899dc56d188ab46fd46d063d85e14b52f3cbed0e9e96813c768acd432a9aad7a706a9b11b1e81fc8388b47e2427a8b83da7e40eabe9d6184b4db940bf24e15176fb08b5907349b056d91c1810987a4",
    "signature_hex": "30440220395301c5a6cb8e39eeb10422873e97319b132404dccef23b4b77f351ae71bab1022079cf1e1f703fcd45d501c17470b9bca9ac3bab48bc98e86ba42ae904f9cba521"
  },
  "sm3": {
    "digest_hex": "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b",
    "digest_b64": "CIDvtGF2ACxs0dlLzD2dkWFIjgmTF9NKTWsot77O82s="
  },
  "sm3_hmac": {
    "hmac_hex": "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6",
    "hmac_b64": "PgximsGOKtJ0FaVJcHVlsAY4ctZThOiO4tH4hzWygPY="
  },
  "sm4": {
    "cipher_hex": "47115316cae07888b2ace617031ecca32f717b3c9bbe2603f8468a96b07c908a7fecd76be96749cf5cc8880dfe7aa964ecb4bb7cac840ac954a0af0705b8aaff8354e050a4f0ece1f05c7b51ee",
    "cipher_b64": "rKCfe0yxWea1lL9MDqZ5QAWJR40wqDUk0oBdEcWq+FQp36KHBOahL2AXuAzN90VptYCbvs28QXagbr9dxlCYKSnM2wkjfL+Re+6zBVw=",
    "key_hex": "0123456789abcdeffedcba9876543210",
    "iv_hex": "000102030405060708090a0b"
  },
  "sm4_decrypt": {
    "plaintext": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e",
    "status": "OK"
  }
}
results = {}

try:
    cd = CONSUMER_DATA["sm2_encrypt"]["cipher_hex"]
    dec = SM2Util.decrypt(cd, KEYS["sm2_enc_priv_raw"])
    results["sm2_encrypt_decrypt"] = "PASS" if dec == MSG else "FAIL"
except Exception as e:
    results["sm2_encrypt_decrypt"] = f"FAIL:{e}"

try:
    sd = CONSUMER_DATA["sm2_sign"]["signature_hex"]
    ok = SM2Util.verify_str(MSG, KEYS["sm2_sign_pub_raw"], sd)
    results["sm2_sign_verify"] = "PASS" if ok else "FAIL"
except Exception as e:
    results["sm2_sign_verify"] = f"FAIL:{e}"

try:
    es = CONSUMER_DATA["sm2_encrypt_sign"]
    ok = SM2Util.verify_str(es["cipher_hex"], KEYS["sm2_sign_pub_raw"], es["signature_hex"])
    dec = SM2Util.decrypt(es["cipher_hex"], KEYS["sm2_enc_priv_raw"]) if ok else None
    results["sm2_encryptSign_verifyDecrypt"] = "PASS" if ok and dec == MSG else "FAIL"
except Exception as e:
    results["sm2_encryptSign_verifyDecrypt"] = f"FAIL:{e}"

try:
    sd = CONSUMER_DATA["sm3"]["digest_hex"]
    dig = SM3Util.digest_str(MSG, to_base64=False)
    results["sm3"] = "PASS" if dig == sd else "FAIL"
except Exception as e:
    results["sm3"] = f"FAIL:{e}"

try:
    sd = CONSUMER_DATA["sm3_hmac"]["hmac_hex"]
    hmac = SM3Util.hmac_str(KEYS["sm3_hmac_key"], MSG, to_base64=False)
    results["sm3_hmac"] = "PASS" if hmac == sd else "FAIL"
except Exception as e:
    results["sm3_hmac"] = f"FAIL:{e}"

try:
    cd = CONSUMER_DATA["sm4"]["cipher_hex"]
    sk = hex_to_bytes(KEYS["sm4_key"])
    dec = SM4Util.decrypt_gcm_to_string(sk, cd)
    results["sm4_encrypt_decrypt"] = "PASS" if dec == MSG else "FAIL"
except Exception as e:
    results["sm4_encrypt_decrypt"] = f"FAIL:{e}"

print(json.dumps(results, ensure_ascii=False))
