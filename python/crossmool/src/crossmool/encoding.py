import base64
import re


def is_hex_string(s: str) -> bool:
    if not isinstance(s, str):
        return False
    s = s.strip()
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def is_base64_string(s: str) -> bool:
    if not isinstance(s, str):
        return False
    s = s.strip()
    try:
        # len check: base64 length divisible by 4 (with padding)
        if len(s) % 4 != 0:
            return False
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


def hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.strip())


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def base64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s)


def bytes_to_base64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')


def detect_string_encoding(s: str) -> str:
    s = s.strip()
    if is_hex_string(s):
        return 'hex'
    if is_base64_string(s):
        return 'base64'
    return 'unknown'


def utf8_to_bytes(s: str) -> bytes:
    return s.encode('utf-8')


def bytes_to_utf8(b: bytes) -> str:
    return b.decode('utf-8')
