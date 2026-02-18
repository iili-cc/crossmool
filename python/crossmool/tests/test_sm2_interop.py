import os
import sys
# ensure src is on path for local test runs
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from crossmool import SM2Util


def test_key_generation_and_roundtrip(tmp_path):
    # raw pair
    priv_raw, pub_raw = SM2Util.generate_keypair_raw()

    # generate ASN.1 bytes and parse back
    pub_asn1, priv_asn1 = SM2Util.generate_keypair_asn1_bytes()

    # write samples for manual Java testing into repository tests/testdata
    repo_td = os.path.join(os.path.dirname(__file__), 'testdata')
    os.makedirs(repo_td, exist_ok=True)
    open(os.path.join(repo_td, 'public.spki.der'), 'wb').write(pub_asn1)
    open(os.path.join(repo_td, 'private.pkcs8.der'), 'wb').write(priv_asn1)
    open(os.path.join(repo_td, 'public.spki.der.b64'), 'w').write(SM2Util.generate_keypair_base64()[0])
    open(os.path.join(repo_td, 'private.pkcs8.der.b64'), 'w').write(SM2Util.generate_keypair_base64()[1])

    # parse back using the library parser
    parsed_pub_raw = SM2Util.sm2_public_key_to_raw_hex(pub_asn1)
    parsed_priv_raw = SM2Util.sm2_private_key_to_raw_hex(priv_asn1)

    # original raw from generate_keypair_raw may differ from generate_keypair_asn1_bytes (they are independent calls)
    # But parsing ASN.1 should yield a valid raw hex of expected length
    assert len(parsed_priv_raw) == 64
    assert parsed_pub_raw.startswith('04') and len(parsed_pub_raw) == 130


def test_encrypt_decrypt_and_sign_verify():
    priv_raw, pub_raw = SM2Util.generate_keypair_raw()
    plaintext = "hello crossmool"

    # encrypt/decrypt hex
    cipher_hex = SM2Util.encrypt(plaintext, pub_raw, to_base64=False)
    decrypted = SM2Util.decrypt(cipher_hex, priv_raw)
    assert decrypted == plaintext

    # encrypt/decrypt base64
    cipher_b64 = SM2Util.encrypt(plaintext, pub_raw, to_base64=True)
    decrypted2 = SM2Util.decrypt(cipher_b64, priv_raw)
    assert decrypted2 == plaintext

    # sign (DER hex) and verify
    sig_der_hex = SM2Util.sign(cipher_hex, priv_raw, to_base64=False)
    ok = SM2Util.verify_str(cipher_hex, pub_raw, sig_der_hex)
    assert ok

    # sign base64 and verify
    sig_b64 = SM2Util.sign(cipher_hex, priv_raw, to_base64=True)
    ok2 = SM2Util.verify_str(cipher_hex, pub_raw, sig_b64)
    assert ok2
