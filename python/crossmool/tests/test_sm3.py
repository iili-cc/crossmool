import os
import sys

# ensure src is on path for local test runs
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from crossmool import SM3Util


def test_digest_known_vector():
    # SM3("abc") standard test vector (GB/T 32905-2016)
    data = b"abc"
    assert SM3Util.digest_to_hex(data) == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    assert len(SM3Util.digest(data)) == 32


def test_digest_str_unicode_consistency():
    s = "简体中文 繁體中文 English"
    assert SM3Util.digest_str(s) == SM3Util.digest_str(s)
    assert len(SM3Util.digest_str(s)) == 64
    assert len(SM3Util.digest_str(s, to_base64=True)) == 44  # 32 bytes -> base64


def test_hmac_roundtrip():
    key = SM3Util.generate_hmac_key(32)
    data = b"message"
    hmac_hex = SM3Util.hmac_to_hex(data, key)
    assert len(hmac_hex) == 64
    assert SM3Util.hmac_to_base64(data, key) != hmac_hex


def test_hmac_verify_string_api():
    key_hex = SM3Util.generate_hmac_key_to_str()
    msg = "hello"
    expected = SM3Util.hmac_str(msg, key_hex)
    assert SM3Util.hmac_verify(msg, key_hex, expected)
    assert not SM3Util.hmac_verify(msg + "X", key_hex, expected)


def test_hmac_cross_language_vector():
    # Fixed vector shared with Java/JS (data-first API): HMAC-SM3(MSG, HMAC_KEY_HEX)
    MSG = "Hello, 这是跨语言国密互通性测试数据"
    KEY = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    expected = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"
    assert SM3Util.hmac_str(MSG, KEY) == expected
    assert SM3Util.hmac_verify(MSG, KEY, expected)
