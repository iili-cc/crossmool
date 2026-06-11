#!/usr/bin/env python
"""Python driver - generates test vectors for cross-language interop testing"""
import sys, json, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python', 'crossmool', 'src'))
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
from encoding import bytes_to_hex, bytes_to_base64, hex_to_bytes, utf8_to_bytes

# Fixed test keys
ENC_PRIV_RAW = "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03"
ENC_PUB_RAW = "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
SIGN_PRIV_RAW = "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3"
SIGN_PUB_RAW = "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"
SM4_KEY = "0123456789abcdeffedcba9876543210"
SM4_IV = "000102030405060708090a0b"
HMAC_KEY = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
TEST_MSG = "Hello, 这是跨语言国密互通性测试数据"

def produce():
    """Generate all test vectors"""
    results = {}
    
    # SM2 encrypt
    cipher_hex = SM2Util.encrypt(TEST_MSG, ENC_PUB_RAW, to_base64=False)
    cipher_b64 = SM2Util.encrypt(TEST_MSG, ENC_PUB_RAW, to_base64=True)
    results['sm2_encrypt'] = {'cipher_hex': cipher_hex, 'cipher_b64': cipher_b64}
    
    # SM2 decrypt (test: encrypt then decrypt)
    decrypted = SM2Util.decrypt(cipher_hex, ENC_PRIV_RAW)
    assert decrypted == TEST_MSG, f"SM2 decrypt failed: {decrypted} != {TEST_MSG}"
    results['sm2_decrypt'] = {'plaintext': decrypted, 'status': 'OK'}
    
    # SM2 sign
    sig_hex = SM2Util.sign(TEST_MSG, SIGN_PRIV_RAW, to_base64=False)
    sig_b64 = SM2Util.sign(TEST_MSG, SIGN_PRIV_RAW, to_base64=True)
    results['sm2_sign'] = {'signature_hex': sig_hex, 'signature_b64': sig_b64}
    
    # SM2 verify
    verified = SM2Util.verify_str(TEST_MSG, SIGN_PUB_RAW, sig_hex)
    assert verified, "SM2 verify failed"
    results['sm2_verify'] = {'verified': verified, 'status': 'OK'}
    
    # SM2 encryptSign (use sign key pair for both)
    # encrypt with enc key, sign ciphertext with sign key
    sig_on_cipher = SM2Util.sign(cipher_hex, SIGN_PRIV_RAW, to_base64=False)
    results['sm2_encrypt_sign'] = {
        'cipher_hex': cipher_hex,
        'signature_hex': sig_on_cipher
    }
    
    # SM3 digest
    digest_hex = SM3Util.digest_str(TEST_MSG, to_base64=False)
    digest_b64 = SM3Util.digest_str(TEST_MSG, to_base64=True)
    results['sm3'] = {'digest_hex': digest_hex, 'digest_b64': digest_b64}
    
    # SM3-HMAC
    hmac_hex = SM3Util.hmac_str(HMAC_KEY, TEST_MSG, to_base64=False)
    hmac_b64 = SM3Util.hmac_str(HMAC_KEY, TEST_MSG, to_base64=True)
    results['sm3_hmac'] = {'hmac_hex': hmac_hex, 'hmac_b64': hmac_b64}
    
    # SM4 GCM encrypt
    sm4_key_bytes = hex_to_bytes(SM4_KEY)
    sm4_iv_bytes = hex_to_bytes(SM4_IV)
    sm4_cipher_hex = SM4Util.encrypt_gcm(sm4_key_bytes, utf8_to_bytes(TEST_MSG), to_base64=False)
    sm4_cipher_b64 = SM4Util.encrypt_gcm(sm4_key_bytes, utf8_to_bytes(TEST_MSG), to_base64=True)
    results['sm4'] = {
        'cipher_hex': sm4_cipher_hex,
        'cipher_b64': sm4_cipher_b64,
        'key_hex': SM4_KEY,
        'iv_hex': SM4_IV
    }
    
    # SM4 decrypt
    sm4_decrypted = SM4Util.decrypt_gcm_to_string(sm4_key_bytes, sm4_cipher_hex)
    assert sm4_decrypted == TEST_MSG, f"SM4 decrypt failed: {sm4_decrypted} != {TEST_MSG}"
    results['sm4_decrypt'] = {'plaintext': sm4_decrypted, 'status': 'OK'}
    
    return results

def consume(data):
    """Verify test vectors from another language"""
    results = {}
    
    # SM2 decrypt
    try:
        cipher_hex = data['sm2_encrypt']['cipher_hex']
        dec = SM2Util.decrypt(cipher_hex, ENC_PRIV_RAW)
        results['sm2_decrypt'] = {'status': 'PASS' if dec == TEST_MSG else 'FAIL', 'result': dec}
    except Exception as e:
        results['sm2_decrypt'] = {'status': 'FAIL', 'error': str(e)}
    
    # SM2 verify
    try:
        sig_hex = data['sm2_sign']['signature_hex']
        ok = SM2Util.verify_str(TEST_MSG, SIGN_PUB_RAW, sig_hex)
        results['sm2_verify'] = {'status': 'PASS' if ok else 'FAIL'}
    except Exception as e:
        results['sm2_verify'] = {'status': 'FAIL', 'error': str(e)}
    
    # SM2 verifyDecrypt
    try:
        es = data['sm2_encrypt_sign']
        ok = SM2Util.verify_str(es['cipher_hex'], SIGN_PUB_RAW, es['signature_hex'])
        dec = SM2Util.decrypt(es['cipher_hex'], ENC_PRIV_RAW) if ok else None
        results['sm2_encrypt_sign'] = {
            'verify': 'PASS' if ok else 'FAIL',
            'decrypt': 'PASS' if dec == TEST_MSG else 'FAIL'
        }
    except Exception as e:
        results['sm2_encrypt_sign'] = {'status': 'FAIL', 'error': str(e)}
    
    # SM3
    try:
        expected = data['sm3']['digest_hex']
        actual = SM3Util.digest_str(TEST_MSG, to_base64=False)
        results['sm3'] = {'status': 'PASS' if actual == expected else 'FAIL'}
    except Exception as e:
        results['sm3'] = {'status': 'FAIL', 'error': str(e)}
    
    # SM3-HMAC
    try:
        expected = data['sm3_hmac']['hmac_hex']
        actual = SM3Util.hmac_str(HMAC_KEY, TEST_MSG, to_base64=False)
        results['sm3_hmac'] = {'status': 'PASS' if actual == expected else 'FAIL'}
    except Exception as e:
        results['sm3_hmac'] = {'status': 'FAIL', 'error': str(e)}
    
    # SM4 decrypt
    try:
        cipher_hex = data['sm4']['cipher_hex']
        sm4_key_bytes = hex_to_bytes(SM4_KEY)
        dec = SM4Util.decrypt_gcm_to_string(sm4_key_bytes, cipher_hex)
        results['sm4_decrypt'] = {'status': 'PASS' if dec == TEST_MSG else 'FAIL', 'result': dec}
    except Exception as e:
        results['sm4_decrypt'] = {'status': 'FAIL', 'error': str(e)}
    
    return results

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'produce'
    if mode == 'produce':
        data = produce()
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif mode == 'consume':
        input_file = sys.argv[2] if len(sys.argv) > 2 else None
        if input_file:
            with open(input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = json.loads(sys.stdin.read())
        results = consume(data)
        print(json.dumps(results, ensure_ascii=False, indent=2))
