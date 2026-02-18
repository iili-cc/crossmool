from gmssl import sm3
import base64
from .encoding import bytes_to_hex, bytes_to_base64, hex_to_bytes


class SM3Util:
    @staticmethod
    def digest_to_hex(data: bytes) -> str:
        return sm3.sm3_hash(list(data))

    @staticmethod
    def digest_to_bytes(data: bytes) -> bytes:
        return bytes.fromhex(SM3Util.digest_to_hex(data))

    @staticmethod
    def digest_to_base64(data: bytes) -> str:
        return bytes_to_base64(SM3Util.digest_to_bytes(data))

    @staticmethod
    def hmac(key: bytes, data: bytes) -> bytes:
        # Implement HMAC with SM3 as underlying hash (block size 64 bytes)
        block_size = 64
        if len(key) > block_size:
            key = SM3Util.digest_to_bytes(key)
        if len(key) < block_size:
            key = key + b"\x00" * (block_size - len(key))
        o_key = bytes((b ^ 0x5C) for b in key)
        i_key = bytes((b ^ 0x36) for b in key)
        inner = sm3.sm3_hash(list(i_key + data))
        inner_bytes = bytes.fromhex(inner)
        outer = sm3.sm3_hash(list(o_key + inner_bytes))
        return bytes.fromhex(outer)

    @staticmethod
    def hmac_to_hex(key: bytes, data: bytes) -> str:
        return bytes_to_hex(SM3Util.hmac(key, data))

    @staticmethod
    def hmac_to_base64(key: bytes, data: bytes) -> str:
        return bytes_to_base64(SM3Util.hmac(key, data))
