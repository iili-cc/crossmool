from gmssl import sm2, func
from encoding import (
    is_hex_string,
    is_base64_string,
    hex_to_bytes,
    bytes_to_hex,
    base64_to_bytes,
    bytes_to_base64,
    utf8_to_bytes,
)
from der import DerReader

# SM2 签名/验签使用的用户 ID（与 Java BouncyCastle 保持一致）
USER_ID = b"1234567812345678"

def _ensure_uncompressed_pubhex(hexstr: str) -> str:
    """确保公钥为 uncompressed 格式 (04 + X + Y, 共 66 字节/130 HEX 字符)"""
    s = hexstr.strip().lower()
    if len(s) == 128:
        return '04' + s
    if len(s) == 130 and s.startswith('04'):
        return s
    raise ValueError('Unsupported public key hex length')

def sm2_public_key_to_raw_hex(key_input) -> str:
    """
    将公钥转换为原始 uncompressed 格式 (04 + X + Y, 共 66 字节/130 HEX 字符)
    支持：X.509 SPKI DER (HEX/Base64/bytes), 原始 64/128 字符 HEX
    """
    if isinstance(key_input, bytes):
        b = key_input
    else:
        s = key_input.strip()
        if is_hex_string(s):
            b = hex_to_bytes(s)
        elif is_base64_string(s):
            b = base64_to_bytes(s)
        else:
            return _ensure_uncompressed_pubhex(s)

    # X.509 SPKI DER 格式 (以 0x30 开头)
    if len(b) > 2 and b[0] == 0x30:
        try:
            spki = DerReader(b).read_sequence()
            # Read algorithm identifier (SEQUENCE)
            alg = spki.read_sequence()
            try:
                _ = alg.read_oid()  # EC OID
            except Exception:
                pass
            try:
                _ = alg.read_oid()  # Curve OID
            except Exception:
                pass
            # Read public key BIT STRING
            unused_bits, data = spki.read_bit_string()
            if unused_bits != 0:
                raise ValueError('Unsupported BIT STRING with unused bits')
            raw = bytes_to_hex(data)
            return _ensure_uncompressed_pubhex(raw)
        except Exception as e:
            raise ValueError(f'Failed to parse X.509 public key: {e}')

    # fallback: assume hex string
    return _ensure_uncompressed_pubhex(bytes_to_hex(b))

def sm2_private_key_to_raw_hex(key_input) -> str:
    """
    将私钥转换为原始 32 字节 HEX 格式
    支持：PKCS#8 DER (HEX/Base64/bytes), 原始 64 字符 HEX
    """
    if isinstance(key_input, bytes):
        b = key_input
    else:
        s = key_input.strip()
        if is_hex_string(s):
            if s.startswith('30'):
                b = hex_to_bytes(s)
            else:
                if len(s) == 64:
                    return s.lower()
                b = hex_to_bytes(s)
        elif is_base64_string(s):
            b = base64_to_bytes(s)
        else:
            raise ValueError('Unsupported private key format')

    if len(b) > 2 and b[0] == 0x30:
        # parse PKCS#8 DER format
        try:
            pki = DerReader(b).read_sequence()
            _ = pki.read_integer_bytes()  # version
            _ = pki.read_sequence()  # algorithm
            private_octets = pki.read_octet_string()
            # Parse ECPrivateKey from OCTET STRING
            ec = DerReader(private_octets).read_sequence()
            _ = ec.read_integer_bytes()  # version
            d_octets = ec.read_octet_string()  # private key bytes
            d_hex = bytes_to_hex(d_octets)
            if len(d_hex) < 64:
                d_hex = d_hex.rjust(64, '0')
            return d_hex
        except Exception as e:
            raise ValueError(f'Failed to parse PKCS#8 private key: {e}')

    # fallback: assume raw bytes
    hex_result = bytes_to_hex(b)
    if len(hex_result) < 64:
        hex_result = hex_result.rjust(64, '0')
    return hex_result

def _der_encode_int(i_bytes: bytes) -> bytes:
    """DER 编码 INTEGER"""
    bi = i_bytes.lstrip(b'\x00')
    if not bi:
        bi = b'\x00'
    if bi[0] & 0x80:
        bi = b'\x00' + bi
    length = len(bi)
    if length < 128:
        return b'\x02' + bytes([length]) + bi
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return b'\x02' + bytes([0x80 | len(len_bytes)]) + len_bytes + bi

def _der_encode_sequence(elements: bytes) -> bytes:
    """DER 编码 SEQUENCE"""
    length = len(elements)
    if length < 128:
        return b'\x30' + bytes([length]) + elements
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return b'\x30' + bytes([0x80 | len(len_bytes)]) + len_bytes + elements

def raw_rs_to_der(r_hex: str, s_hex: str) -> bytes:
    """将 r||s 转换为 DER 编码的签名"""
    r = bytes.fromhex(r_hex)
    s = bytes.fromhex(s_hex)
    r_enc = _der_encode_int(r)
    s_enc = _der_encode_int(s)
    return _der_encode_sequence(r_enc + s_enc)

def der_to_raw_rs(der_sig: bytes) -> (str, str):
    """将 DER 编码的签名转换为 r||s（去除 DER INTEGER 的符号填充）"""
    d = DerReader(der_sig).read_sequence()
    r = d.read_integer_bytes()
    s = d.read_integer_bytes()
    # 去除 DER INTEGER 可能添加的前导 0x00（用于表示正数）
    r = r.lstrip(b'\x00') or b'\x00'
    s = s.lstrip(b'\x00') or b'\x00'
    r_hex = bytes_to_hex(r).rjust(64, '0')
    s_hex = bytes_to_hex(s).rjust(64, '0')
    return r_hex, s_hex

class SM2Util:
    """
    SM2 加密解密签名验签工具类
    与 Java BouncyCastle SM2Engine(C1C3C2) 和 SM2Signer 兼容
    
    完全基于 gmssl 库的底层实现，确保与 Java BouncyCastle 的互通性
    """
    
    @staticmethod
    def generate_keypair_raw() -> (str, str):
        """生成原始密钥对 (private_hex, public_hex)"""
        priv = func.random_hex(64)
        temp_crypt = sm2.CryptSM2(private_key=priv, public_key='04' + '00' * 64)
        pub = temp_crypt._kg(int(priv, 16), temp_crypt.ecc_table['g'])
        if not pub.startswith('04'):
            pub = '04' + pub
        return priv.lower(), pub.lower()

    @staticmethod
    def encrypt_to_hex(content: bytes, public_key) -> str:
        """
        加密 SM2 明文（C1C3C2 格式，与 Java Bouncy Castle 兼容）
        使用 gmssl 库内置的 encrypt 方法
        """
        pub_hex = sm2_public_key_to_raw_hex(public_key)
        # 使用临时 CryptSM2 对象进行加密（只需要公钥）
        crypt = sm2.CryptSM2(public_key=pub_hex, private_key='', mode=1)
        enc_bytes = crypt.encrypt(content)
        return enc_bytes.hex()

    @staticmethod
    def encrypt_to_base64(content: bytes, public_key) -> str:
        hex_out = SM2Util.encrypt_to_hex(content, public_key)
        return bytes_to_base64(bytes.fromhex(hex_out))

    @staticmethod
    def decrypt_from_hex(cipher_hex: str, private_key, public_key=None) -> bytes:
        """
        解密 SM2 密文（C1C3C2 格式，与 Java Bouncy Castle 兼容）
        Java: SM2Engine(SM2Engine.Mode.C1C3C2)
        
        使用 gmssl 库内置的 decrypt 方法（默认 C1C3C2 格式）
        """
        priv_hex = sm2_private_key_to_raw_hex(private_key)
        
        # 获取或推导公钥
        if public_key is not None:
            pub_hex = sm2_public_key_to_raw_hex(public_key)
        else:
            # 从私钥推导公钥
            temp_crypt = sm2.CryptSM2(private_key=priv_hex, public_key='04' + '00' * 64)
            pub_hex = temp_crypt._kg(int(priv_hex, 16), temp_crypt.ecc_table['g'])
            if not pub_hex.startswith('04'):
                pub_hex = '04' + pub_hex
        
        # 使用 gmssl 内置 decrypt 方法 (默认 C1C3C2 格式)
        # gmssl decrypt 接受 bytes 类型的密文
        crypt = sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, mode=1)
        cipher_bytes = bytes.fromhex(cipher_hex)
        result = crypt.decrypt(cipher_bytes)
        if isinstance(result, str):
            result = result.encode('latin-1')
        return bytes(result)

    @staticmethod
    def decrypt_from_base64(cipher_b64: str, private_key) -> bytes:
        cipher_bytes = base64_to_bytes(cipher_b64)
        return SM2Util.decrypt_from_hex(bytes_to_hex(cipher_bytes), private_key)

    @staticmethod
    def sign_to_der(content: bytes, private_key) -> bytes:
        """
        签名 SM2 明文，返回 DER 编码的签名
        Java: SM2Signer 使用 USER_ID="1234567812345678"
        gmssl 的 sign_with_sm3 方法默认使用 USER_ID = b"1234567812345678"
        """
        priv_hex = sm2_private_key_to_raw_hex(private_key)
        
        # gmssl sign 需要 public_key，先从私钥推导公钥
        temp_crypt = sm2.CryptSM2(private_key=priv_hex, public_key='04' + '00' * 64)
        pub_hex = temp_crypt._kg(int(priv_hex, 16), temp_crypt.ecc_table['g'])
        if not pub_hex.startswith('04'):
            pub_hex = '04' + pub_hex
        
        crypt = sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex)
        # sign_with_sm3 uses SM3 hash and auto-generates random K
        sig_raw = crypt.sign_with_sm3(content)  # returns hex r||s
        
        if len(sig_raw) % 2 != 0:
            raise ValueError('Invalid signature length')
        half = len(sig_raw) // 2
        r = sig_raw[:half]
        s = sig_raw[half:]
        return raw_rs_to_der(r, s)

    @staticmethod
    def sign_to_hex(content: bytes, private_key) -> str:
        return SM2Util.sign_to_der(content, private_key).hex()

    @staticmethod
    def sign_to_base64(content: bytes, private_key) -> str:
        return bytes_to_base64(SM2Util.sign_to_der(content, private_key))

    @staticmethod
    def verify(content: bytes, public_key, signature) -> bool:
        """
        验签 SM2 签名
        Java: SM2Signer 使用 USER_ID="1234567812345678"
        gmssl 的 verify 方法默认使用 USER_ID = b"1234567812345678"
        """
        pub_hex = sm2_public_key_to_raw_hex(public_key)
        
        # signature may be hex/base64/bytes; convert to raw r||s hex
        sig_bytes = None
        if isinstance(signature, bytes):
            sig_bytes = signature
        else:
            s = signature.strip()
            if is_hex_string(s):
                sig_bytes = bytes.fromhex(s)
            elif is_base64_string(s):
                sig_bytes = base64_to_bytes(s)
            else:
                raise ValueError('Unsupported signature encoding')

        # if DER (starts with 0x30) decode
        if len(sig_bytes) > 0 and sig_bytes[0] == 0x30:
            r_hex, s_hex = der_to_raw_rs(sig_bytes)
            sig_raw = (r_hex + s_hex)
        else:
            sig_raw = sig_bytes.hex()

        crypt = sm2.CryptSM2(public_key=pub_hex, private_key=None)
        return crypt.verify_with_sm3(sig_raw, content)

    # convenience wrappers similar to Java API
    @staticmethod
    def encrypt(content: str, public_key, to_base64: bool = False) -> str:
        b = utf8_to_bytes(content)
        return SM2Util.encrypt_to_base64(b, public_key) if to_base64 else SM2Util.encrypt_to_hex(b, public_key)

    @staticmethod
    def decrypt(cipher_text: str, private_key) -> str:
        s = cipher_text.strip()
        if is_hex_string(s):
            dec = SM2Util.decrypt_from_hex(s, private_key)
        else:
            dec = SM2Util.decrypt_from_base64(s, private_key)
        return dec.decode('utf-8')

    @staticmethod
    def sign(content: str, private_key, to_base64: bool = False) -> str:
        b = utf8_to_bytes(content)
        if to_base64:
            return SM2Util.sign_to_base64(b, private_key)
        return SM2Util.sign_to_hex(b, private_key)

    @staticmethod
    def verify_str(content: str, public_key, signature: str) -> bool:
        return SM2Util.verify(utf8_to_bytes(content), public_key, signature)