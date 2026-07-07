from gmssl import sm3
from os import urandom
from encoding import (
    bytes_to_hex, bytes_to_base64, hex_to_bytes, base64_to_bytes,
    is_hex_string, is_base64_string
)

class SM3Util:
    @staticmethod
    def digest(data: bytes) -> bytes:
        return bytes.fromhex(sm3.sm3_hash(list(data)))

    @staticmethod
    def digest_to_hex(data: bytes) -> str:
        return sm3.sm3_hash(list(data))

    @staticmethod
    def digest_to_bytes(data: bytes) -> bytes:
        return SM3Util.digest(data)

    @staticmethod
    def digest_to_base64(data: bytes) -> str:
        return bytes_to_base64(SM3Util.digest(data))

    @staticmethod
    def digest_to_str(data: bytes, to_base64: bool = False) -> str:
        digest_bytes = SM3Util.digest(data)
        if to_base64:
            return bytes_to_base64(digest_bytes)
        return bytes_to_hex(digest_bytes)

    @staticmethod
    def digest_str(input_str: str, to_base64: bool = False) -> str:
        if not input_str or not input_str.strip():
            raise ValueError("input_str cannot be empty")
        data = input_str.encode('utf-8')
        digest_bytes = SM3Util.digest(data)
        if to_base64:
            return bytes_to_base64(digest_bytes)
        return bytes_to_hex(digest_bytes)

    @staticmethod
    def hmac(key: bytes, data: bytes) -> bytes:
        block_size = 64
        if len(key) > block_size:
            key = SM3Util.digest(key)
        if len(key) < block_size:
            key = key + b"\x00" * (block_size - len(key))
        o_key = bytes((b ^ 0x5C) for b in key)
        i_key = bytes((b ^ 0x36) for b in key)
        inner = sm3.sm3_hash(list(i_key + data))
        inner_bytes = bytes.fromhex(inner)
        outer = sm3.sm3_hash(list(o_key + inner_bytes))
        return bytes.fromhex(outer)

    @staticmethod
    def hmac_from_str(key_str: str, data_str: str) -> bytes:
        if not key_str or not key_str.strip():
            raise ValueError("key_str cannot be empty")
        if not data_str or not data_str.strip():
            raise ValueError("data_str cannot be empty")

        if is_hex_string(key_str):
            key_bytes = hex_to_bytes(key_str)
        elif is_base64_string(key_str):
            key_bytes = base64_to_bytes(key_str)
        else:
            raise ValueError("key_str must be Hex string or Base64 string")

        if is_hex_string(data_str):
            data_bytes = hex_to_bytes(data_str)
        elif is_base64_string(data_str):
            data_bytes = base64_to_bytes(data_str)
        else:
            data_bytes = data_str.encode('utf-8')

        return SM3Util.hmac(key_bytes, data_bytes)

    @staticmethod
    def hmac_to_hex(key: bytes, data: bytes) -> str:
        return bytes_to_hex(SM3Util.hmac(key, data))

    @staticmethod
    def hmac_to_base64(key: bytes, data: bytes) -> str:
        return bytes_to_base64(SM3Util.hmac(key, data))

    @staticmethod
    def hmac_to_str(key: bytes, data: bytes, to_base64: bool = False) -> str:
        hmac_bytes = SM3Util.hmac(key, data)
        if to_base64:
            return bytes_to_base64(hmac_bytes)
        return bytes_to_hex(hmac_bytes)

    @staticmethod
    def hmac_str(key_str: str, data_str: str, to_base64: bool = False) -> str:
        hmac_bytes = SM3Util.hmac_from_str(key_str, data_str)
        if to_base64:
            return bytes_to_base64(hmac_bytes)
        return bytes_to_hex(hmac_bytes)

    @staticmethod
    def generate_hmac_key(key_length: int = 32) -> bytes:
        if key_length < 32:
            raise ValueError("key_length must be >= 32")
        return urandom(key_length)

    @staticmethod
    def generate_hmac_key_to_str(key_length: int = 32, to_base64: bool = False) -> str:
        key_bytes = SM3Util.generate_hmac_key(key_length)
        if to_base64:
            return bytes_to_base64(key_bytes)
        return bytes_to_hex(key_bytes)

    @staticmethod
    def hmac_verify(key_str: str, data_str: str, received_hmac: str) -> bool:
        """Verify HMAC by computing expected value and comparing."""
        return SM3Util.hmac_str(key_str, data_str) == received_hmac
        return bytes_to_hex(key_bytes)