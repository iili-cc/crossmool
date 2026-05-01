from gmssl import sm4
from encoding import bytes_to_hex, hex_to_bytes, bytes_to_base64, base64_to_bytes

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError('Invalid padding')
    return data[:-pad_len]

class SM4Util:
    @staticmethod
    def generate_key() -> bytes:
        from os import urandom

        return urandom(16)

    @staticmethod
    def generate_key_hex() -> str:
        return bytes_to_hex(SM4Util.generate_key())

    @staticmethod
    def encrypt_ecb_hex(key: bytes, plain_bytes: bytes) -> str:
        if len(key) != 16:
            raise ValueError('SM4 key must be 16 bytes')
        crypt = sm4.CryptSM4()
        crypt.set_key(key, sm4.SM4_ENCRYPT)
        data = pkcs7_pad(plain_bytes)
        enc = crypt.crypt_ecb(data)
        return bytes_to_hex(enc)

    @staticmethod
    def decrypt_ecb_hex(key: bytes, hex_cipher: str) -> bytes:
        if len(key) != 16:
            raise ValueError('SM4 key must be 16 bytes')
        crypt = sm4.CryptSM4()
        crypt.set_key(key, sm4.SM4_DECRYPT)
        cipher_bytes = hex_to_bytes(hex_cipher)
        dec = crypt.crypt_ecb(cipher_bytes)
        return pkcs7_unpad(dec)

    @staticmethod
    def encrypt_ecb_base64(key: bytes, plain_bytes: bytes) -> str:
        hex_out = SM4Util.encrypt_ecb_hex(key, plain_bytes)
        return bytes_to_base64(hex_to_bytes(hex_out))

    @staticmethod
    def decrypt_ecb_base64(key: bytes, b64_cipher: str) -> bytes:
        cipher = base64_to_bytes(b64_cipher)
        return SM4Util.decrypt_ecb_hex(key, bytes_to_hex(cipher))