import os
import sys

# ensure src is on path for local test runs
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from crossmool import SM4Util


def test_generate_key():
    key = SM4Util.generate_key()
    assert len(key) == 16
    assert len(SM4Util.generate_key_hex()) == 32
    assert len(SM4Util.generate_key_base64()) == 24  # 16 bytes -> base64 (with padding)


def test_encrypt_decrypt_hex_and_base64():
    key = SM4Util.generate_key()
    plaintext = "SM4 GCM 简体中文 繁體中文 English".encode('utf-8')

    enc_hex = SM4Util.encrypt_gcm(key, plaintext, to_base64=False)
    assert SM4Util.decrypt_gcm(key, enc_hex) == plaintext

    enc_b64 = SM4Util.encrypt_gcm(key, plaintext, to_base64=True)
    assert SM4Util.decrypt_gcm(key, enc_b64) == plaintext


def test_string_api_roundtrip():
    key = SM4Util.generate_key()
    plaintext = "hello SM4 string 简体中文"
    enc = SM4Util.encrypt_gcm_string(key, plaintext)
    assert SM4Util.decrypt_gcm_to_string(key, enc) == plaintext


def test_random_iv_produces_different_ciphertext():
    key = SM4Util.generate_key()
    ct1 = SM4Util.encrypt_gcm(key, b"same plaintext")
    ct2 = SM4Util.encrypt_gcm(key, b"same plaintext")
    assert ct1 != ct2


def test_tamper_detection():
    key = SM4Util.generate_key()
    enc_hex = SM4Util.encrypt_gcm(key, b"secret", to_base64=False)
    tampered = enc_hex[:-2] + "00"
    try:
        SM4Util.decrypt_gcm(key, tampered)
        assert False, "expected ValueError for tampered ciphertext"
    except ValueError:
        pass
