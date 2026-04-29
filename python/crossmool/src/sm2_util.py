from gmssl import sm2, func
try:
    from .encoding import (
        is_hex_string,
        is_base64_string,
        hex_to_bytes,
        bytes_to_hex,
        base64_to_bytes,
        bytes_to_base64,
        utf8_to_bytes,
    )
except ImportError:
    from encoding import (
        is_hex_string,
        is_base64_string,
        hex_to_bytes,
        bytes_to_hex,
        base64_to_bytes,
        bytes_to_base64,
        utf8_to_bytes,
    )
from .der import DerReader


USER_ID = b"0123456789ABCDEF"


def _ensure_uncompressed_pubhex(hexstr: str) -> str:
    s = hexstr.strip().lower()
    if len(s) == 128:
        return '04' + s
    if len(s) == 130 and s.startswith('04'):
        return s
    raise ValueError('Unsupported public key hex length')


def sm2_public_key_to_raw_hex(key_input) -> str:
    if isinstance(key_input, bytes):
        b = key_input
    else:
        s = key_input.strip()
        if is_hex_string(s):
            b = hex_to_bytes(s)
        elif is_base64_string(s):
            b = base64_to_bytes(s)
        else:
            # treat as raw hex-like
            return _ensure_uncompressed_pubhex(s)

    # looks like DER if starts with 0x30
    if len(b) > 2 and b[0] == 0x30:
        spki = DerReader(b).read_sequence()
        alg = spki.read_sequence()
        try:
            alg_oid = alg.read_oid()
        except Exception:
            alg_oid = None
        try:
            curve_oid = alg.read_oid()
        except Exception:
            pass
        unused_bits, data = spki.read_bit_string()
        if unused_bits != 0:
            raise ValueError('Unsupported BIT STRING with unused bits')
        raw = bytes_to_hex(data)
        return _ensure_uncompressed_pubhex(raw)

    # fallback: assume hex string
    return _ensure_uncompressed_pubhex(bytes_to_hex(b))


def sm2_private_key_to_raw_hex(key_input) -> str:
    if isinstance(key_input, bytes):
        b = key_input
    else:
        s = key_input.strip()
        if is_hex_string(s):
            # if starts with '30' may be DER
            if s.startswith('30'):
                b = hex_to_bytes(s)
            else:
                # raw private 32-byte hex
                if len(s) == 64:
                    return s.lower()
                b = hex_to_bytes(s)
        elif is_base64_string(s):
            b = base64_to_bytes(s)
        else:
            raise ValueError('Unsupported private key format')

    if len(b) > 2 and b[0] == 0x30:
        # parse PKCS8
        pki = DerReader(b).read_sequence()
        _ = pki.read_integer_bytes()
        alg = pki.read_sequence()
        try:
            _ = alg.read_oid()
        except Exception:
            pass
        try:
            _ = alg.read_oid()
        except Exception:
            pass
        private_octets = pki.read_octet_string()
        ec = DerReader(private_octets).read_sequence()
        _ = ec.read_integer_bytes()
        d_octets = ec.read_octet_string()
        d_hex = bytes_to_hex(d_octets)
        # left pad to 32 bytes
        if len(d_hex) < 64:
            d_hex = d_hex.rjust(64, '0')
        return d_hex

    # fallback
    return bytes_to_hex(b)


def _der_encode_int(i_bytes: bytes) -> bytes:
    # INTEGER tag 0x02
    # remove leading zeros
    bi = i_bytes.lstrip(b'\x00')
    if not bi:
        bi = b'\x00'
    # if highest bit set, prefix 0x00
    if bi[0] & 0x80:
        bi = b'\x00' + bi
    length = len(bi)
    if length < 128:
        return b'\x02' + bytes([length]) + bi
    # long form
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return b'\x02' + bytes([0x80 | len(len_bytes)]) + len_bytes + bi


def _der_encode_sequence(elements: bytes) -> bytes:
    length = len(elements)
    if length < 128:
        return b'\x30' + bytes([length]) + elements
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return b'\x30' + bytes([0x80 | len(len_bytes)]) + len_bytes + elements


def raw_rs_to_der(r_hex: str, s_hex: str) -> bytes:
    r = bytes.fromhex(r_hex)
    s = bytes.fromhex(s_hex)
    r_enc = _der_encode_int(r)
    s_enc = _der_encode_int(s)
    return _der_encode_sequence(r_enc + s_enc)


def der_to_raw_rs(der_sig: bytes) -> (str, str):
    d = DerReader(der_sig).read_sequence()
    r = d.read_integer_bytes()
    s = d.read_integer_bytes()
    # left pad to 32 bytes
    r_hex = bytes_to_hex(r).rjust(64, '0')
    s_hex = bytes_to_hex(s).rjust(64, '0')
    return r_hex, s_hex


class SM2Util:
    @staticmethod
    def generate_keypair_raw() -> (str, str):
        # returns (private_hex, public_hex) where public_hex is uncompressed (04 + X + Y)
        priv = func.random_hex(64)
        crypt = sm2.CryptSM2(public_key=None, private_key=priv)
        pub = crypt._kg(int(priv, 16), crypt.ecc_table['g'])
        # _kg returns without leading 04 sometimes; ensure
        if not pub.startswith('04'):
            pub = '04' + pub
        return priv.lower(), pub.lower()

    # --------------------- DER/ASN.1 writers for interoperability ---------------------
    @staticmethod
    def _encode_oid(oid: str) -> bytes:
        # OID: first two nodes encoded as 40*X+Y, rest base128
        parts = [int(x) for x in oid.split('.')]
        if len(parts) < 2:
            raise ValueError('Invalid OID')
        first = 40 * parts[0] + parts[1]
        body = bytes([first])
        for n in parts[2:]:
            # base128 encoding, MSB set except last
            if n == 0:
                body += b'\x00'
                continue
            stack = []
            v = n
            while v > 0:
                stack.append(v & 0x7F)
                v >>= 7
            for i in range(len(stack) - 1, -1, -1):
                byte = stack[i]
                if i != 0:
                    byte |= 0x80
                body += bytes([byte])
        # OID tag 0x06
        if len(body) < 128:
            return b'\x06' + bytes([len(body)]) + body
        lb = len(body).to_bytes((len(body).bit_length() + 7) // 8, 'big')
        return b'\x06' + bytes([0x80 | len(lb)]) + lb + body

    @staticmethod
    def _encode_octet_string(data: bytes) -> bytes:
        if len(data) < 128:
            return b'\x04' + bytes([len(data)]) + data
        lb = len(data).to_bytes((len(data).bit_length() + 7) // 8, 'big')
        return b'\x04' + bytes([0x80 | len(lb)]) + lb + data

    @staticmethod
    def _encode_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
        payload = bytes([unused_bits]) + data
        if len(payload) < 128:
            return b'\x03' + bytes([len(payload)]) + payload
        lb = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, 'big')
        return b'\x03' + bytes([0x80 | len(lb)]) + lb + payload

    @staticmethod
    def _encode_context_specific(tag_no: int, content: bytes) -> bytes:
        # constructed context-specific: 0xA0 | tag_no for tag_no < 31
        if tag_no < 31:
            tag = 0xA0 | tag_no
            if len(content) < 128:
                return bytes([tag]) + bytes([len(content)]) + content
            lb = len(content).to_bytes((len(content).bit_length() + 7) // 8, 'big')
            return bytes([tag]) + bytes([0x80 | len(lb)]) + lb + content
        raise NotImplementedError('High tag numbers not supported')

    @staticmethod
    def encode_spki_from_pubhex(pub_hex: str) -> bytes:
        # SubjectPublicKeyInfo { algorithm { oid ecPublicKey, oid sm2curve }, subjectPublicKey BIT STRING }
        OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
        OID_SM2_CURVE = '1.2.156.10197.1.301'
        pub_hex = pub_hex.lower()
        if pub_hex.startswith('04'):
            raw = bytes.fromhex(pub_hex[2:])
        else:
            raw = bytes.fromhex(pub_hex)
        alg_seq = SM2Util._der_encode_sequence(SM2Util._encode_oid(OID_EC_PUBLIC_KEY) + SM2Util._encode_oid(OID_SM2_CURVE))
        # SPKI's BIT STRING should contain the public key bytes prefixed by 0x04 (uncompressed)
        pub_payload = (b'\x04' + raw) if not pub_hex.startswith('04') else bytes.fromhex(pub_hex)
        bitstr = SM2Util._encode_bit_string(pub_payload, 0)
        spki = SM2Util._der_encode_sequence(alg_seq + bitstr)
        return spki

    @staticmethod
    def encode_pkcs8_from_privpub(priv_hex: str, pub_hex: str) -> bytes:
        # PrivateKeyInfo (PKCS#8): SEQ { version(0), alg(seq{oid ec, oid sm2}), privateKey OCTETSTRING(ECPrivateKey) }
        OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
        OID_SM2_CURVE = '1.2.156.10197.1.301'
        d = bytes.fromhex(priv_hex)
        # ECPrivateKey: SEQ { version INTEGER 1, privateKey OCTET STRING, [1] publicKey BIT STRING }
        int_ver = _der_encode_int(b'\x01')
        oct_d = SM2Util._encode_octet_string(d)
        pub_hex = pub_hex.lower()
        if pub_hex.startswith('04'):
            pub_bytes = bytes.fromhex(pub_hex[2:])
            pub_payload = b'\x04' + pub_bytes
        else:
            pub_bytes = bytes.fromhex(pub_hex)
            pub_payload = b'\x04' + pub_bytes
        bitstr = SM2Util._encode_bit_string(pub_payload, 0)
        ctx_pub = SM2Util._encode_context_specific(1, bitstr)
        ec_seq = SM2Util._der_encode_sequence(int_ver + oct_d + ctx_pub)

        alg_seq = SM2Util._der_encode_sequence(SM2Util._encode_oid(OID_EC_PUBLIC_KEY) + SM2Util._encode_oid(OID_SM2_CURVE))
        priv_oct = SM2Util._encode_octet_string(ec_seq)
        pkcs8 = SM2Util._der_encode_sequence(_der_encode_int(b'\x00') + alg_seq + priv_oct)
        return pkcs8

    @staticmethod
    def generate_keypair_asn1_bytes() -> (bytes, bytes):
        # returns (public_spki_bytes, private_pkcs8_bytes)
        priv_hex, pub_hex = SM2Util.generate_keypair_raw()
        spki = SM2Util.encode_spki_from_pubhex(pub_hex)
        pkcs8 = SM2Util.encode_pkcs8_from_privpub(priv_hex, pub_hex)
        return spki, pkcs8

    @staticmethod
    def generate_keypair_base64() -> (str, str):
        pub_bytes, priv_bytes = SM2Util.generate_keypair_asn1_bytes()
        return bytes_to_base64(pub_bytes), bytes_to_base64(priv_bytes)

    @staticmethod
    def generate_keypair_hex() -> (str, str):
        pub_bytes, priv_bytes = SM2Util.generate_keypair_asn1_bytes()
        return bytes_to_hex(pub_bytes), bytes_to_hex(priv_bytes)

    @staticmethod
    def encrypt_to_hex(content: bytes, public_key) -> str:
        pub_hex = sm2_public_key_to_raw_hex(public_key)
        crypt = sm2.CryptSM2(public_key=pub_hex, private_key='')
        cipher_hex = crypt.encrypt(content, cipher_mode=1)
        return cipher_hex

    @staticmethod
    def encrypt_to_base64(content: bytes, public_key) -> str:
        hex_out = SM2Util.encrypt_to_hex(content, public_key)
        return bytes_to_base64(bytes.fromhex(hex_out))

    @staticmethod
    def decrypt_from_hex(cipher_hex: str, private_key) -> bytes:
        priv_hex = sm2_private_key_to_raw_hex(private_key)
        crypt = sm2.CryptSM2(public_key=None, private_key=priv_hex)
        return crypt.decrypt(cipher_hex, cipher_mode=1)

    @staticmethod
    def decrypt_from_base64(cipher_b64: str, private_key) -> bytes:
        cipher_bytes = base64_to_bytes(cipher_b64)
        return SM2Util.decrypt_from_hex(bytes_to_hex(cipher_bytes), private_key)

    @staticmethod
    def sign_to_der(content: bytes, private_key) -> bytes:
        priv_hex = sm2_private_key_to_raw_hex(private_key)
        crypt = sm2.CryptSM2(public_key=None, private_key=priv_hex)
        sig_raw = crypt.sign(content)  # returns hex r||s
        # split into r and s
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
        return crypt.verify(sig_raw, content)

    # convenience wrappers similar to Java API
    @staticmethod
    def encrypt(content: str, public_key, to_base64: bool = False) -> str:
        b = utf8_to_bytes(content)
        return SM2Util.encrypt_to_base64(b, public_key) if to_base64 else SM2Util.encrypt_to_hex(b, public_key)

    @staticmethod
    def decrypt(cipher_text: str, private_key) -> str:
        # detect hex or base64
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
