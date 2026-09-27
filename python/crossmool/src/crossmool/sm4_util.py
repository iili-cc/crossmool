from os import urandom
from crossmool.encoding import (
    bytes_to_hex, hex_to_bytes, bytes_to_base64, base64_to_bytes,
    is_hex_string, is_base64_string
)
from gmssl import sm4

GCM_IV_SIZE = 12   # 96 bits
GCM_TAG_SIZE = 16  # 128 bits
BLOCK_SIZE = 16

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _inc32(counter: bytes) -> bytes:
    """GCM counter increment (increment the rightmost 32 bits)"""
    counter_int = int.from_bytes(counter, 'big')
    low_32 = (counter_int & 0xFFFFFFFF) + 1
    result = (counter_int & ~0xFFFFFFFF) | (low_32 & 0xFFFFFFFF)
    return result.to_bytes(16, 'big')

def _gf128_mul(x: int, y: int) -> int:
    """Multiply two elements in GF(2^128) with reduction polynomial x^128+x^7+x^2+x+1"""
    R = 0xE1000000000000000000000000000000
    MASK = (1 << 128) - 1
    z = 0
    v = y
    for i in range(128):
        if x & (1 << (127 - i)):
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z & MASK

def _ghash(h: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """GHASH computation for GCM"""
    h_int = int.from_bytes(h, 'big')

    aad_padded = aad + b'\x00' * ((16 - len(aad) % 16) % 16)
    ct_padded = ciphertext + b'\x00' * ((16 - len(ciphertext) % 16) % 16)
    len_block = (len(aad) * 8).to_bytes(8, 'big') + (len(ciphertext) * 8).to_bytes(8, 'big')

    y = 0
    for i in range(0, len(aad_padded), 16):
        y ^= int.from_bytes(aad_padded[i:i + 16], 'big')
        y = _gf128_mul(y, h_int)
    for i in range(0, len(ct_padded), 16):
        y ^= int.from_bytes(ct_padded[i:i + 16], 'big')
        y = _gf128_mul(y, h_int)
    y ^= int.from_bytes(len_block, 'big')
    y = _gf128_mul(y, h_int)

    return y.to_bytes(16, 'big')

def _sm4_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt a single 16-byte block using SM4 ECB (no padding)"""
    crypt = sm4.CryptSM4()
    crypt.set_key(key, sm4.SM4_ENCRYPT)
    return crypt.crypt_ecb(block)[:16]

def _sm4_ctr_encrypt(key: bytes, counter: bytes, plaintext: bytes) -> bytes:
    """SM4 CTR mode encryption"""
    result = bytearray()
    for i in range(0, len(plaintext), BLOCK_SIZE):
        keystream = _sm4_ecb_encrypt_block(key, counter)
        block = plaintext[i:i + BLOCK_SIZE]
        result.extend(_xor_bytes(keystream[:len(block)], block))
        counter = _inc32(counter)
    return bytes(result)

def _detect_and_decode(s: str) -> bytes:
    """Auto-detect Hex/Base64 encoding and decode to bytes"""
    if is_hex_string(s):
        return hex_to_bytes(s)
    if is_base64_string(s):
        return base64_to_bytes(s)
    raise ValueError("Input string must be Hex or Base64 encoded")

class SM4Util:
    @staticmethod
    def generate_key() -> bytes:
        return urandom(16)

    @staticmethod
    def generate_key_hex() -> str:
        return bytes_to_hex(SM4Util.generate_key())

    @staticmethod
    def generate_key_base64() -> str:
        return bytes_to_base64(SM4Util.generate_key())

    @staticmethod
    def parse_hex_key(hex_key: str) -> bytes:
        return hex_to_bytes(hex_key)

    @staticmethod
    def encrypt_gcm(key: bytes, plaintext: bytes, aad: bytes = b'', to_base64: bool = False) -> str:
        """
        SM4 GCM encrypt; returns Hex(IV[12] + ciphertext + Tag[16]) or Base64.
        """
        if len(key) != 16:
            raise ValueError('SM4 key must be 16 bytes')

        iv = urandom(GCM_IV_SIZE)
        j0 = iv + b'\x00\x00\x00\x01'
        h = _sm4_ecb_encrypt_block(key, b'\x00' * 16)
        ciphertext = _sm4_ctr_encrypt(key, _inc32(j0), plaintext)
        ghash_result = _ghash(h, aad, ciphertext)
        j0_encrypted = _sm4_ecb_encrypt_block(key, j0)
        tag = _xor_bytes(ghash_result, j0_encrypted)

        combined = iv + ciphertext + tag
        if to_base64:
            return bytes_to_base64(combined)
        return bytes_to_hex(combined)

    @staticmethod
    def decrypt_gcm(key: bytes, ciphertext_str: str, aad: bytes = b'') -> bytes:
        """
        SM4 GCM decrypt; auto-detects Hex/Base64 input encoding.
        """
        if len(key) != 16:
            raise ValueError('SM4 key must be 16 bytes')

        combined = _detect_and_decode(ciphertext_str)
        if len(combined) < GCM_IV_SIZE + GCM_TAG_SIZE:
            raise ValueError('Invalid GCM ciphertext: too short')

        iv = combined[:GCM_IV_SIZE]
        tag = combined[-GCM_TAG_SIZE:]
        ciphertext = combined[GCM_IV_SIZE:-GCM_TAG_SIZE]

        j0 = iv + b'\x00\x00\x00\x01'
        h = _sm4_ecb_encrypt_block(key, b'\x00' * 16)
        ghash_result = _ghash(h, aad, ciphertext)
        j0_encrypted = _sm4_ecb_encrypt_block(key, j0)
        computed_tag = _xor_bytes(ghash_result, j0_encrypted)

        if computed_tag != tag:
            raise ValueError('SM4 GCM decryption failed (authentication failed)')

        return _sm4_ctr_encrypt(key, _inc32(j0), ciphertext)

    @staticmethod
    def encrypt_gcm_hex(key: bytes, plaintext: bytes, aad: bytes = b'') -> str:
        return SM4Util.encrypt_gcm(key, plaintext, aad, to_base64=False)

    @staticmethod
    def decrypt_gcm_from_hex(key: bytes, hex_str: str, aad: bytes = b'') -> bytes:
        if not is_hex_string(hex_str):
            raise ValueError("Input must be Hex encoded")
        return SM4Util.decrypt_gcm(key, hex_str, aad)

    @staticmethod
    def encrypt_gcm_string(key: bytes, plain_text: str, to_base64: bool = False) -> str:
        return SM4Util.encrypt_gcm(key, plain_text.encode('utf-8'), to_base64=to_base64)

    @staticmethod
    def decrypt_gcm_to_string(key: bytes, ciphertext_str: str) -> str:
        return SM4Util.decrypt_gcm(key, ciphertext_str).decode('utf-8')

if __name__ == '__main__':
    key = SM4Util.generate_key()
    hex_key = SM4Util.generate_key_hex()
    print(f'Key (HEX): {hex_key}')

    plain_text = 'Hello, 這是国密SM4測試數據'
    print(f'Plaintext: {plain_text}')

    encrypted_hex = SM4Util.encrypt_gcm_string(key, plain_text)
    print(f'Encrypted (Hex): {encrypted_hex}')

    encrypted_b64 = SM4Util.encrypt_gcm_string(key, plain_text, to_base64=True)
    print(f'Encrypted (Base64): {encrypted_b64}')

    decrypted = SM4Util.decrypt_gcm_to_string(key, encrypted_hex)
    print(f'Decrypted from Hex: {decrypted}')

    decrypted_b64 = SM4Util.decrypt_gcm_to_string(key, encrypted_b64)
    print(f'Decrypted from Base64: {decrypted_b64}')

    assert decrypted == plain_text, 'Decryption failed!'
    assert decrypted_b64 == plain_text, 'Decryption from Base64 failed!'
    print('GCM test passed!')