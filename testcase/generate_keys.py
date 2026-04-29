#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 密钥对生成脚本

为 8 种编程语言（java, c, cpp, csharp, golang, javascript, python, rust）
生成 keys 目录下的 JSON 密钥文件，包含加密公钥和签名私钥的 Hex 和 Base64 格式。

输出格式：
{
  "encryption_public_key": {
    "hex": "公钥 Hex 字符串",
    "base64": "公钥 Base64 字符串"
  },
  "signature_private_key": {
    "hex": "私钥 Hex 字符串",
    "base64": "私钥 Base64 字符串"
  }
}
"""

import json
import os
import sys
from pathlib import Path

# 添加 Python 模块路径
src_dir = Path(__file__).parent.parent / "python" / "crossmool" / "src"
sys.path.insert(0, str(src_dir))

# 直接导入依赖模块，避免相对导入问题
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
from gmssl import sm2, func

# 复制 SM2Util 的核心功能
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
            return _ensure_uncompressed_pubhex(s)
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
    return _ensure_uncompressed_pubhex(bytes_to_hex(b))

def sm2_private_key_to_raw_hex(key_input) -> str:
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
        if len(d_hex) < 64:
            d_hex = d_hex.rjust(64, '0')
        return d_hex
    return bytes_to_hex(b)

class SM2Util:
    @staticmethod
    def generate_keypair_raw() -> (str, str):
        priv = func.random_hex(64)
        # gmssl 3.x API: CryptSM2(private_key, public_key) - use empty string for public_key
        crypt = sm2.CryptSM2(priv, '')
        pub = crypt._kg(int(priv, 16), crypt.ecc_table['g'])
        if not pub.startswith('04'):
            pub = '04' + pub
        return priv.lower(), pub.lower()

    @staticmethod
    def _encode_oid(oid: str) -> bytes:
        parts = [int(x) for x in oid.split('.')]
        if len(parts) < 2:
            raise ValueError('Invalid OID')
        first = 40 * parts[0] + parts[1]
        body = bytes([first])
        for n in parts[2:]:
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
        if tag_no < 31:
            tag = 0xA0 | tag_no
            if len(content) < 128:
                return bytes([tag]) + bytes([len(content)]) + content
            lb = len(content).to_bytes((len(content).bit_length() + 7) // 8, 'big')
            return bytes([tag]) + bytes([0x80 | len(lb)]) + lb + content
        raise NotImplementedError('High tag numbers not supported')

    @staticmethod
    def _der_encode_int(i_bytes: bytes) -> bytes:
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

    @staticmethod
    def _der_encode_sequence(elements: bytes) -> bytes:
        length = len(elements)
        if length < 128:
            return b'\x30' + bytes([length]) + elements
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return b'\x30' + bytes([0x80 | len(len_bytes)]) + len_bytes + elements

    @staticmethod
    def encode_spki_from_pubhex(pub_hex: str) -> bytes:
        OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
        OID_SM2_CURVE = '1.2.156.10197.1.301'
        pub_hex = pub_hex.lower()
        if pub_hex.startswith('04'):
            raw = bytes.fromhex(pub_hex[2:])
        else:
            raw = bytes.fromhex(pub_hex)
        alg_seq = SM2Util._der_encode_sequence(SM2Util._encode_oid(OID_EC_PUBLIC_KEY) + SM2Util._encode_oid(OID_SM2_CURVE))
        pub_payload = (b'\x04' + raw) if not pub_hex.startswith('04') else bytes.fromhex(pub_hex)
        bitstr = SM2Util._encode_bit_string(pub_payload, 0)
        spki = SM2Util._der_encode_sequence(alg_seq + bitstr)
        return spki

    @staticmethod
    def encode_pkcs8_from_privpub(priv_hex: str, pub_hex: str) -> bytes:
        OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
        OID_SM2_CURVE = '1.2.156.10197.1.301'
        d = bytes.fromhex(priv_hex)
        int_ver = SM2Util._der_encode_int(b'\x01')
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
        pkcs8 = SM2Util._der_encode_sequence(SM2Util._der_encode_int(b'\x00') + alg_seq + priv_oct)
        return pkcs8

    @staticmethod
    def generate_keypair_asn1_bytes() -> (bytes, bytes):
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

# 支持的 8 种编程语言
LANGUAGES = ["java", "c", "cpp", "csharp", "golang", "javascript", "python", "rust"]

# 密钥输出目录
KEYS_DIR = Path(__file__).parent / "keys"

def generate_keys_for_language(language: str) -> dict:
    """
    为指定语言生成 SM2 密钥对
    
    Args:
        language: 语言名称
        
    Returns:
        密钥对字典，包含 Hex 和 Base64 格式
    """
    # 生成 Hex 格式的密钥对（公钥，私钥）
    pub_hex, priv_hex = SM2Util.generate_keypair_hex()
    
    # 生成 Base64 格式的密钥对（公钥，私钥）
    pub_base64, priv_base64 = SM2Util.generate_keypair_base64()
    
    return {
        "encryption_public_key": {
            "hex": pub_hex,
            "base64": pub_base64
        },
        "signature_private_key": {
            "hex": priv_hex,
            "base64": priv_base64
        }
    }

def save_keys_to_file(language: str, keys: dict) -> Path:
    """
    将密钥对保存到 JSON 文件
    
    Args:
        language: 语言名称
        keys: 密钥对字典
        
    Returns:
        保存的文件路径
    """
    # 创建语言子目录
    lang_dir = KEYS_DIR / language
    lang_dir.mkdir(parents=True, exist_ok=True)
    
    # 保存密钥文件
    output_file = lang_dir / "keys.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2, ensure_ascii=False)
    
    return output_file

def main():
    """主函数：为所有语言生成密钥对"""
    print("=" * 60)
    print("SM2 密钥对生成脚本")
    print("=" * 60)
    print(f"输出目录：{KEYS_DIR}")
    print(f"支持的语言：{', '.join(LANGUAGES)}")
    print("=" * 60)
    
    generated_files = []
    
    for language in LANGUAGES:
        print(f"\n[{language}] 生成密钥对...")
        
        try:
            # 生成密钥对
            keys = generate_keys_for_language(language)
            
            # 保存密钥文件
            output_file = save_keys_to_file(language, keys)
            generated_files.append(output_file)
            
            print(f"  [OK] 公钥 (Hex): {keys['encryption_public_key']['hex'][:40]}...")
            print(f"  [OK] 私钥 (Hex): {keys['signature_private_key']['hex'][:40]}...")
            print(f"  [OK] 已保存至：{output_file}")
            
        except Exception as e:
            print(f"  [FAIL] 生成失败：{e}")
            continue
    
    print("\n" + "=" * 60)
    print(f"密钥生成完成！共生成 {len(generated_files)} 个密钥文件")
    print("=" * 60)
    
    # 显示生成的文件列表
    if generated_files:
        print("\n生成的密钥文件:")
        for file_path in generated_files:
            print(f"  - {file_path}")

if __name__ == "__main__":
    main()