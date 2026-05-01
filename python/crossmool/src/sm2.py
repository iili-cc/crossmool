#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM2 国密算法实现 - 与 Java BouncyCastle 完全兼容
- 加密/解密：C1C3C2 模式
- 密钥格式：X.509 (公钥), PKCS#8 (私钥), DER 编码
- 签名/验签：USER_ID = "1234567812345678"
"""

import hashlib
from typing import Tuple, Optional
from gmssl import sm2, sm3

# SM2 曲线参数 (sm2p256v1)
SM2_A = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
SM2_B = "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4FE24F0B4"
SM2_N = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
SM2_Gx = "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
SM2_Gy = "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

# USER_ID for signature (same as Java)
USER_ID = "1234567812345678"
USER_ID_BYTES = USER_ID.encode('utf-8')

class SM2KeyUtil:
    """SM2 密钥工具类 - 与 Java SM2KeyUtil 对应"""
    
    @staticmethod
    def convert_string_to_bytes(key_str: str) -> bytes:
        """
        转换密钥字符串为字节数组，支持 Hex 和 Base64 格式
        :param key_str: Hex 或 Base64 字符串
        :return: 字节数组
        """
        import base64
        if not key_str or not key_str.strip():
            raise ValueError("key_str must not be null or empty")
        key_str = key_str.strip()
        # 判断是 Hex 还是 Base64
        if all(c in '0123456789abcdefABCDEF' for c in key_str):
            return bytes.fromhex(key_str)
        else:
            return base64.b64decode(key_str)
    
    @staticmethod
    def parse_x509_public_key(pub_key_bytes: bytes) -> str:
        """
        解析 X.509 格式的公钥，提取原始公钥 (04 + X + Y)
        :param pub_key_bytes: X.509 DER 编码的公钥字节
        :return: Hex 格式的原始公钥 (04 + 32 字节 X + 32 字节 Y)
        """
        return SM2KeyUtil._parse_x509_manual(pub_key_bytes)
    
    @staticmethod
    def _parse_x509_manual(pub_key_bytes: bytes) -> str:
        """手动解析 X.509 公钥"""
        # X.509 SPKI 格式：
        # SEQUENCE {
        #   SEQUENCE { OID, OID }  (算法标识符)
        #   BIT STRING { 04 || X || Y }  (公钥数据)
        # }
        i = 0
        if pub_key_bytes[i] != 0x30:
            raise ValueError("Invalid X.509 format: expected SEQUENCE")
        i += 1
        seq_len = pub_key_bytes[i]
        i += 1
        
        # 跳过算法标识符 SEQUENCE
        if pub_key_bytes[i] != 0x30:
            raise ValueError("Invalid X.509 format: expected SEQUENCE for algorithm")
        i += 1
        alg_len = pub_key_bytes[i]
        i += 1 + alg_len
        
        # 读取 BIT STRING
        if pub_key_bytes[i] != 0x03:
            raise ValueError("Invalid X.509 format: expected BIT STRING")
        i += 1
        bit_len = pub_key_bytes[i]
        i += 1
        
        # BIT STRING 的第一个字节是未使用的位数 (通常为 0)
        if pub_key_bytes[i] != 0:
            raise ValueError("Invalid BIT STRING padding")
        i += 1
        
        # 剩余的字节就是公钥数据 (04 + X + Y)
        pub_key_raw = pub_key_bytes[i:]
        return pub_key_raw.hex()
    
    @staticmethod
    def parse_pkcs8_private_key(priv_key_bytes: bytes) -> str:
        """
        解析 PKCS#8 格式的私钥，提取原始私钥 (32 字节)
        :param priv_key_bytes: PKCS#8 DER 编码的私钥字节
        :return: Hex 格式的原始私钥 (32 字节 = 64 字符)
        """
        return SM2KeyUtil._parse_pkcs8_manual(priv_key_bytes)
    
    @staticmethod
    def _read_length(data: bytes, offset: int) -> Tuple[int, int]:
        """读取 DER 长度值，返回 (长度，新的偏移量)"""
        length = data<offset>
        if length < 0x80:
            # 短格式：直接是长度
            return length, offset + 1
        else:
            # 长格式：高 7 位表示后续长度字节的数量
            num_bytes = length & 0x7F
            length = int.from_bytes(data[offset+1:offset+1+num_bytes], 'big')
            return length, offset + 1 + num_bytes
    
    @staticmethod
    def _parse_pkcs8_manual(priv_key_bytes: bytes) -> str:
        """手动解析 PKCS#8 私钥
        
        PKCS#8 格式：
        SEQUENCE {
          INTEGER (version)
          SEQUENCE { OID, OID } (算法标识符)
          OCTET STRING {
            SEQUENCE {  (ECPrivateKey)
              INTEGER (version)
              OCTET STRING (private key)
              ...
            }
          }
        }
        """
        i = 0
        # 外层 SEQUENCE
        if priv_key_bytes[i] != 0x30:
            raise ValueError("Invalid PKCS#8 format: expected SEQUENCE")
        i += 1
        seq_len, i = SM2KeyUtil._read_length(priv_key_bytes, i)
        
        # 版本 INTEGER (PKCS#8 version)
        if priv_key_bytes[i] != 0x02:
            raise ValueError("Invalid PKCS#8 format: expected INTEGER for version")
        i += 1
        ver_len, i = SM2KeyUtil._read_length(priv_key_bytes, i)
        i += ver_len
        
        # 算法标识符 SEQUENCE
        if priv_key_bytes[i] != 0x30:
            raise ValueError("Invalid PKCS#8 format: expected SEQUENCE for algorithm")
        i += 1
        alg_len, i = SM2KeyUtil._read_length(priv_key_bytes, i)
        i += alg_len
        
        # OCTET STRING (包含 ECPrivateKey)
        if priv_key_bytes[i] != 0x04:
            raise ValueError("Invalid PKCS#8 format: expected OCTET STRING")
        i += 1
        oct_len, i = SM2KeyUtil._read_length(priv_key_bytes, i)
        
        # ECPrivateKey SEQUENCE
        if priv_key_bytes[i] != 0x30:
            raise ValueError("Invalid ECPrivateKey format: expected SEQUENCE")
        i += 1
        ec_seq_len, i = SM2KeyUtil._read_length(priv_key_bytes, i)
        
        # ECPrivateKey 版本 INTEGER
        if priv_key_bytes[i] != 0x02:
            raise ValueError("Invalid ECPrivateKey format: expected INTEGER for version")
        i += 1
        ec_ver_len, i = SM2KeyUtil._read_length(priv_key_bytes, i)
        i += ec_ver_len
        
        # 私钥 OCTET STRING
        if priv_key_bytes[i] != 0x04:
            raise ValueError("Invalid ECPrivateKey format: expected OCTET STRING for private key")
        i += 1
        priv_len, i = SM2KeyUtil._read_length(priv_key_bytes, i)
        
        # 获取私钥数据
        priv_key_raw = priv_key_bytes[i:i+priv_len]
        priv_key_hex = priv_key_raw.hex()
        
        # 确保私钥是 32 字节 (64 hex 字符)
        if len(priv_key_hex) < 64:
            priv_key_hex = priv_key_hex.zfill(64)
        elif len(priv_key_hex) > 64:
            # 如果超过 64 字符，取后 64 字符
            priv_key_hex = priv_key_hex[-64:]
        
        return priv_key_hex

class SM2Util:
    """SM2 加密解密签名验签工具类 - 与 Java SM2Util 完全兼容"""
    
    def __init__(self, encryption_pub_key: Optional[str] = None,
                 encryption_priv_key: Optional[str] = None,
                 signature_pub_key: Optional[str] = None,
                 signature_priv_key: Optional[str] = None):
        """
        初始化 SM2 工具
        :param encryption_pub_key: 加密公钥 (X.509 DER 编码 Hex/Base64)
        :param encryption_priv_key: 解密私钥 (PKCS#8 DER 编码 Hex/Base64)
        :param signature_pub_key: 验签公钥 (X.509 DER 编码 Hex/Base64)
        :param signature_priv_key: 签名私钥 (PKCS#8 DER 编码 Hex/Base64)
        """
        self.encryption_pub_key = encryption_pub_key
        self.encryption_priv_key = encryption_priv_key
        self.signature_pub_key = signature_pub_key
        self.signature_priv_key = signature_priv_key
        
        # 解析原始密钥
        self._enc_pub_raw = None
        self._enc_priv_raw = None
        self._sig_pub_raw = None
        self._sig_priv_raw = None
        
        if encryption_pub_key:
            self._enc_pub_raw = SM2KeyUtil.parse_x509_public_key(
                SM2KeyUtil.convert_string_to_bytes(encryption_pub_key)
            )
        if encryption_priv_key:
            self._enc_priv_raw = SM2KeyUtil.parse_pkcs8_private_key(
                SM2KeyUtil.convert_string_to_bytes(encryption_priv_key)
            )
        if signature_pub_key:
            self._sig_pub_raw = SM2KeyUtil.parse_x509_public_key(
                SM2KeyUtil.convert_string_to_bytes(signature_pub_key)
            )
        if signature_priv_key:
            self._sig_priv_raw = SM2KeyUtil.parse_pkcs8_private_key(
                SM2KeyUtil.convert_string_to_bytes(signature_priv_key)
            )
    
    def encrypt(self, plaintext: str, pub_key: Optional[str] = None) -> str:
        """
        加密 (C1C3C2 模式)
        :param plaintext: 明文
        :param pub_key: 公钥 (可选，优先使用构造函数中的)
        :return: Hex 格式的密文
        """
        if not plaintext:
            raise ValueError("plaintext must not be null or empty")
        
        key = pub_key or self.encryption_pub_key
        if not key:
            raise ValueError("public key must be provided")
        
        pub_raw = SM2KeyUtil.parse_x509_public_key(
            SM2KeyUtil.convert_string_to_bytes(key)
        )
        
        # 使用 gmssl 加密 (mode=1 表示 C1C3C2)
        crypt = sm2.CryptSM2(public_key=pub_raw, mode=1)
        ciphertext = crypt.encrypt(plaintext.encode('utf-8'))
        return ciphertext.hex()
    
    def decrypt(self, ciphertext_hex: str, priv_key: Optional[str] = None) -> str:
        """
        解密 (C1C3C2 模式)
        :param ciphertext_hex: Hex 格式的密文
        :param priv_key: 私钥 (可选，优先使用构造函数中的)
        :return: 明文字符串
        """
        if not ciphertext_hex:
            raise ValueError("ciphertext must not be null or empty")
        
        key = priv_key or self.encryption_priv_key
        if not key:
            raise ValueError("private key must be provided")
        
        priv_raw = SM2KeyUtil.parse_pkcs8_private_key(
            SM2KeyUtil.convert_string_to_bytes(key)
        )
        pub_raw = self._enc_pub_raw
        
        # 使用 gmssl 解密 (mode=1 表示 C1C3C2)
        crypt = sm2.CryptSM2(private_key=priv_raw, public_key=pub_raw, mode=1)
        plaintext_bytes = crypt.decrypt(bytes.fromhex(ciphertext_hex))
        return plaintext_bytes.decode('utf-8')
    
    def sign(self, content: str, priv_key: Optional[str] = None) -> str:
        """
        签名
        :param content: 待签名内容
        :param priv_key: 私钥 (可选，优先使用构造函数中的)
        :return: Hex 格式的签名 (DER 编码)
        """
        if not content:
            raise ValueError("content must not be null or empty")
        
        key = priv_key or self.signature_priv_key
        if not key:
            raise ValueError("private key must be provided")
        
        priv_raw = SM2KeyUtil.parse_pkcs8_private_key(
            SM2KeyUtil.convert_string_to_bytes(key)
        )
        
        # 计算 USER_ID 的 SM3 哈希
        user_id_hash = sm3.sm3_hash(USER_ID_BYTES)
        
        # 使用 gmssl 签名
        crypt = sm2.CryptSM2(private_key=priv_raw, mode=1)
        signature = crypt.sign(content.encode('utf-8'), user_id_hash)
        return signature.hex()
    
    def verify(self, content: str, signature_hex: str, pub_key: Optional[str] = None) -> bool:
        """
        验签
        :param content: 原始内容
        :param signature_hex: Hex 格式的签名
        :param pub_key: 公钥 (可选，优先使用构造函数中的)
        :return: 验证结果
        """
        if not content:
            raise ValueError("content must not be null or empty")
        if not signature_hex:
            raise ValueError("signature must not be null or empty")
        
        key = pub_key or self.signature_pub_key
        if not key:
            raise ValueError("public key must be provided")
        
        pub_raw = SM2KeyUtil.parse_x509_public_key(
            SM2KeyUtil.convert_string_to_bytes(key)
        )
        
        # 计算 USER_ID 的 SM3 哈希
        user_id_hash = sm3.sm3_hash(USER_ID_BYTES)
        
        # 使用 gmssl 验签
        crypt = sm2.CryptSM2(public_key=pub_raw, mode=1)
        return crypt.verify(content.encode('utf-8'), bytes.fromhex(signature_hex), user_id_hash)

# 便捷函数
def encrypt(plaintext: str, public_key: str) -> str:
    """加密"""
    util = SM2Util(encryption_pub_key=public_key)
    return util.encrypt(plaintext)

def decrypt(ciphertext_hex: str, private_key: str, public_key: str = None) -> str:
    """解密"""
    util = SM2Util(encryption_priv_key=private_key, encryption_pub_key=public_key)
    return util.decrypt(ciphertext_hex)

def sign(content: str, private_key: str) -> str:
    """签名"""
    util = SM2Util(signature_priv_key=private_key)
    return util.sign(content)

def verify(content: str, signature_hex: str, public_key: str) -> bool:
    """验签"""
    util = SM2Util(signature_pub_key=public_key)
    return util.verify(content, signature_hex)


