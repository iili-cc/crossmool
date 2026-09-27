import os
import sys

# ensure src is on path for local test runs
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from crossmool import SM2Util


def test_key_generation_lengths():
    priv_raw, pub_raw = SM2Util.generate_keypair_raw()
    assert len(priv_raw) == 64
    assert pub_raw.startswith('04') and len(pub_raw) == 130

    kp_hex = SM2Util.generate_keypair_hex()
    assert len(kp_hex['privateKey']) == 64
    assert len(kp_hex['publicKey']) == 130

    kp_b64 = SM2Util.generate_keypair_base64()
    assert 'publicKey' in kp_b64 and 'privateKey' in kp_b64


def test_encrypt_decrypt_roundtrip():
    priv_raw, pub_raw = SM2Util.generate_keypair_raw()
    plaintext = "hello crossmool 简体中文 繁體中文 English"

    cipher_hex = SM2Util.encrypt(plaintext, pub_raw, to_base64=False)
    assert SM2Util.decrypt(cipher_hex, priv_raw) == plaintext

    cipher_b64 = SM2Util.encrypt(plaintext, pub_raw, to_base64=True)
    assert SM2Util.decrypt(cipher_b64, priv_raw) == plaintext


def test_sign_verify_roundtrip():
    priv_raw, pub_raw = SM2Util.generate_keypair_raw()
    content = "sign me 123"

    sig_hex = SM2Util.sign(content, priv_raw, to_base64=False)
    assert SM2Util.verify_str(content, pub_raw, sig_hex)

    sig_b64 = SM2Util.sign(content, priv_raw, to_base64=True)
    assert SM2Util.verify_str(content, pub_raw, sig_b64)


def test_encrypt_sign_verify_decrypt():
    kp1 = SM2Util.generate_keypair_hex()
    kp2 = SM2Util.generate_keypair_hex()
    content = "combined flow 简体中文"

    pair = SM2Util.encrypt_sign(content, kp1['publicKey'], kp2['privateKey'])
    recovered = SM2Util.verify_decrypt(
        pair['ciphertext'], pair['signature'], kp2['publicKey'], kp1['privateKey']
    )
    assert recovered == content


def test_pem_roundtrip():
    priv_raw, pub_raw = SM2Util.generate_keypair_raw()

    pub_pem = SM2Util.export_public_key_pem(pub_raw)
    assert SM2Util.import_public_key_pem(pub_pem) == pub_raw

    pri_pem = SM2Util.export_private_key_pem(priv_raw, pub_raw)
    assert SM2Util.import_private_key_pem(pri_pem) == priv_raw


def test_der_signature_roundtrip():
    priv_raw, pub_raw = SM2Util.generate_keypair_raw()
    content = b"raw bytes signature"

    der_sig = SM2Util.sign_to_der(content, priv_raw)
    assert der_sig[0] == 0x30  # DER SEQUENCE
    assert SM2Util.verify(content, pub_raw, der_sig)
