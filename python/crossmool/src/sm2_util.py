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

# ────────────────── DER key encoding helpers ──────────────────

OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
OID_SM2_CURVE = '1.2.156.10197.1.301'

def _der_encode_oid(oid: str) -> bytes:
    """DER encode an OID string."""
    parts = [int(x) for x in oid.split('.')]
    result = [parts[0] * 40 + parts[1]]
    for v in parts[2:]:
        stack = [v & 0x7f]
        v >>= 7
        while v > 0:
            stack.insert(0, (v & 0x7f) | 0x80)
            v >>= 7
        result.extend(stack)
    content = bytes(result)
    if len(content) < 128:
        return b'\x06' + bytes([len(content)]) + content
    len_bytes = len(content).to_bytes((len(content).bit_length() + 7) // 8, 'big')
    return b'\x06' + bytes([0x80 | len(len_bytes)]) + len_bytes + content

def _der_encode_octet_string(data: bytes) -> bytes:
    if len(data) < 128:
        return b'\x04' + bytes([len(data)]) + data
    len_bytes = len(data).to_bytes((len(data).bit_length() + 7) // 8, 'big')
    return b'\x04' + bytes([0x80 | len(len_bytes)]) + len_bytes + data

def _der_encode_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    content = bytes([unused_bits]) + data
    if len(content) < 128:
        return b'\x03' + bytes([len(content)]) + content
    len_bytes = len(content).to_bytes((len(content).bit_length() + 7) // 8, 'big')
    return b'\x03' + bytes([0x80 | len(len_bytes)]) + len_bytes + content

def _der_encode_context_specific(tag_number: int, content: bytes) -> bytes:
    tag = 0xa0 | tag_number
    if len(content) < 128:
        return bytes([tag, len(content)]) + content
    len_bytes = len(content).to_bytes((len(content).bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(len_bytes)]) + len_bytes + content

def _encode_public_key_to_der(pub_hex: str) -> bytes:
    """Encode raw-hex public key (130 chars, 04+X+Y) to X.509 SPKI DER."""
    pub_bytes = bytes.fromhex(pub_hex)  # 65 bytes
    alg_seq = _der_encode_sequence(
        _der_encode_oid(OID_EC_PUBLIC_KEY) + _der_encode_oid(OID_SM2_CURVE)
    )
    return _der_encode_sequence(alg_seq + _der_encode_bit_string(pub_bytes, 0))

def _encode_private_key_to_der(priv_hex: str, pub_hex: str) -> bytes:
    """Encode raw-hex keys to PKCS#8 PrivateKeyInfo DER."""
    d = bytes.fromhex(priv_hex)  # 32 bytes
    pub = bytes.fromhex(pub_hex)  # 65 bytes
    # ECPrivateKey (SEC1)
    ec_priv = _der_encode_sequence(
        _der_encode_int(b'\x01') +
        _der_encode_octet_string(d) +
        _der_encode_context_specific(1, _der_encode_bit_string(pub, 0))
    )
    # AlgorithmIdentifier
    alg_seq = _der_encode_sequence(
        _der_encode_oid(OID_EC_PUBLIC_KEY) + _der_encode_oid(OID_SM2_CURVE)
    )
    return _der_encode_sequence(
        _der_encode_int(b'\x00') + alg_seq + _der_encode_octet_string(ec_priv)
    )

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
    def generate_keypair_hex() -> dict:
        """生成 HEX 密钥对，返回 {'publicKey': ..., 'privateKey': ...}（公钥 130 字符，私钥 64 字符）"""
        priv_hex, pub_hex = SM2Util.generate_keypair_raw()
        return {'publicKey': pub_hex, 'privateKey': priv_hex}

    @staticmethod
    def generate_keypair_base64() -> dict:
        """生成 Base64 密钥对，返回 {'publicKey': ..., 'privateKey': ...}"""
        priv_hex, pub_hex = SM2Util.generate_keypair_raw()
        return {
            'publicKey': bytes_to_base64(hex_to_bytes(pub_hex)),
            'privateKey': bytes_to_base64(hex_to_bytes(priv_hex))
        }

    @staticmethod
    def encrypt_to_hex(content: bytes, public_key) -> str:
        """
        加密 SM2 明文（C1C3C2 格式，与 Java/Go 兼容）
        
        标准 C1C3C2 格式: 04||X(32)||Y(32)||C3(32)||C2(msg_len)
        gmssl 内置 encrypt 返回 64 字节 C1（无 04 前缀），
        这里补上 04 前缀以兼容 Go/Java 的标准 C1C3C2 格式
        """
        pub_hex = sm2_public_key_to_raw_hex(public_key)
        crypt = sm2.CryptSM2(public_key=pub_hex, private_key='', mode=1)
        enc_bytes = crypt.encrypt(content)
        # gmssl: C1(64 bytes) + C3(32) + C2(msg_len)
        # -> 标准: C1(65 bytes with 04) + C3(32) + C2(msg_len)
        enc_bytes = b'\x04' + enc_bytes[:64] + enc_bytes[64:]
        return enc_bytes.hex()

    @staticmethod
    def encrypt_to_bytes(content: bytes, public_key) -> bytes:
        """加密 SM2 明文，返回 C1C3C2 密文字节数组。"""
        return bytes.fromhex(SM2Util.encrypt_to_hex(content, public_key))

    @staticmethod
    def decrypt_from_bytes(cipher_bytes: bytes, private_key) -> bytes:
        """解密 C1C3C2 密文字节数组，返回明文字节数组。"""
        return SM2Util.decrypt_from_hex(cipher_bytes.hex(), private_key)

    @staticmethod
    def encrypt_to_base64(content: bytes, public_key) -> str:
        hex_out = SM2Util.encrypt_to_hex(content, public_key)
        return bytes_to_base64(bytes.fromhex(hex_out))

    @staticmethod
    def decrypt_from_hex(cipher_hex: str, private_key, public_key=None) -> bytes:
        """
        解密 SM2 密文（C1C3C2 格式，兼容 Java/Go/Python）
        
        支持两种 C1C3C2 格式:
        - 标准格式 (Java/Go): C1(65 bytes, 04+X+Y) + C3(32) + C2(msg_len)
        - gmssl 格式: C1(64 bytes, X+Y) + C3(32) + C2(msg_len)
        自动检测并处理
        """
        priv_hex = sm2_private_key_to_raw_hex(private_key)
        
        # 获取或推导公钥
        if public_key is not None:
            pub_hex = sm2_public_key_to_raw_hex(public_key)
        else:
            temp_crypt = sm2.CryptSM2(private_key=priv_hex, public_key='04' + '00' * 64)
            pub_hex = temp_crypt._kg(int(priv_hex, 16), temp_crypt.ecc_table['g'])
            if not pub_hex.startswith('04'):
                pub_hex = '04' + pub_hex
        
        cipher_bytes = bytes.fromhex(cipher_hex)
        
        # gmssl 内置 decrypt 期望 C1 无 04 前缀 (64 bytes)
        # 如果输入是标准格式 (C1 以 04 开头，共 65 bytes)，去掉 04 前缀
        if len(cipher_bytes) > 0 and cipher_bytes[0] == 0x04:
            # 标准: 04||X(32)||Y(32)||C3(32)||C2(msg_len) = 1+32+32+32+msg_len
            # -> gmssl: X(32)||Y(32)||C3(32)||C2(msg_len) = 32+32+32+msg_len
            cipher_bytes = cipher_bytes[1:65] + cipher_bytes[65:97] + cipher_bytes[97:]
        
        crypt = sm2.CryptSM2(private_key=priv_hex, public_key=pub_hex, mode=1)
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

    # ────────────────── Encrypt+Sign / Verify+Decrypt ──────────────────

    @staticmethod
    def encrypt_sign(content: str, enc_public_key, sign_private_key, to_base64: bool = False) -> dict:
        """Encrypt and sign UTF-8 content. Returns {'ciphertext': ..., 'signature': ...}."""
        ct = SM2Util.encrypt(content, enc_public_key, to_base64=to_base64)
        sig = SM2Util.sign(content, sign_private_key, to_base64=to_base64)
        return {'ciphertext': ct, 'signature': sig}

    @staticmethod
    def verify_decrypt(ciphertext: str, signature: str, sign_public_key, dec_private_key) -> str:
        """Verify signature then decrypt. Returns UTF-8 plaintext."""
        if not SM2Util.verify_str(ciphertext, sign_public_key, signature):
            raise ValueError('SM2 signature verification failed')
        return SM2Util.decrypt(ciphertext, dec_private_key)

    # ────────────────── PEM Export / Import ──────────────────

    @staticmethod
    def export_public_key_pem(pub_hex: str) -> str:
        """Export raw-hex public key (130 chars) as PEM (X.509 SubjectPublicKeyInfo)."""
        der = _encode_public_key_to_der(pub_hex)
        b64 = bytes_to_base64(der)
        lines = ['-----BEGIN PUBLIC KEY-----']
        for i in range(0, len(b64), 64):
            lines.append(b64[i:i + 64])
        lines.append('-----END PUBLIC KEY-----')
        return '\n'.join(lines)

    @staticmethod
    def export_private_key_pem(priv_hex: str, pub_hex: str) -> str:
        """Export raw-hex keys as PEM (PKCS#8 PrivateKeyInfo)."""
        der = _encode_private_key_to_der(priv_hex, pub_hex)
        b64 = bytes_to_base64(der)
        lines = ['-----BEGIN PRIVATE KEY-----']
        for i in range(0, len(b64), 64):
            lines.append(b64[i:i + 64])
        lines.append('-----END PRIVATE KEY-----')
        return '\n'.join(lines)

    @staticmethod
    def import_public_key_pem(pem: str) -> str:
        """Import PEM (X.509 SPKI) and return raw-hex public key (130 chars)."""
        begin = '-----BEGIN PUBLIC KEY-----'
        end = '-----END PUBLIC KEY-----'
        s = pem.find(begin)
        e = pem.find(end)
        if s == -1 or e == -1:
            raise ValueError('Invalid PEM: missing PUBLIC KEY boundaries')
        b64 = pem[s + len(begin):e].replace('\n', '').replace('\r', '').replace(' ', '')
        der = base64_to_bytes(b64)
        return sm2_public_key_to_raw_hex(der)

    @staticmethod
    def import_private_key_pem(pem: str) -> str:
        """Import PEM (PKCS#8) and return raw-hex private key (64 chars)."""
        begin = '-----BEGIN PRIVATE KEY-----'
        end = '-----END PRIVATE KEY-----'
        s = pem.find(begin)
        e = pem.find(end)
        if s == -1 or e == -1:
            raise ValueError('Invalid PEM: missing PRIVATE KEY boundaries')
        b64 = pem[s + len(begin):e].replace('\n', '').replace('\r', '').replace(' ', '')
        der = base64_to_bytes(b64)
        return sm2_private_key_to_raw_hex(der)