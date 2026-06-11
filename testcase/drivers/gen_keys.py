#!/usr/bin/env python
"""Generate fixed test keys for cross-language interop testing"""
import sys
sys.path.insert(0, 'D:/workspaces/git/corssmool/crossmool/python/crossmool/src')
from sm2_util import SM2Util
from encoding import bytes_to_hex, bytes_to_base64

enc_priv, enc_pub = SM2Util.generate_keypair_raw()
sign_priv, sign_pub = SM2Util.generate_keypair_raw()

sm4_key = "0123456789abcdeffedcba9876543210"
sm4_iv = "000102030405060708090a0b"
hmac_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
test_msg = "Hello, 这是跨语言国密互通性测试数据"

print(f"SM2_ENC_PRIVATE_KEY_RAW={enc_priv}")
print(f"SM2_ENC_PUBLIC_KEY_RAW={enc_pub}")
print(f"SM2_SIGN_PRIVATE_KEY_RAW={sign_priv}")
print(f"SM2_SIGN_PUBLIC_KEY_RAW={sign_pub}")
print(f"SM4_KEY={sm4_key}")
print(f"SM4_IV={sm4_iv}")
print(f"HMAC_KEY={hmac_key}")
print(f"TEST_MSG={test_msg}")
