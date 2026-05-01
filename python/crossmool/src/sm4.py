#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SM4 国密分组加密算法实现 - 与 Java BouncyCastle 完全兼容
"""

from gmssl import sm4
from typing import Optional

class SM4Util:
    """SM4 加密工具类"""
    
    def __init__(self, key: bytes, mode: str = 'CBC', iv: Optional[bytes] = None):
        """
        初始化 SM4 工具
        :param key: 16 字节密钥
        :param mode: 加密模式 ('ECB', 'CBC', 'CTR', 'CFB', 'OFB')
        :param iv: 初始化向量 (CBC/CFB/OFB/CTR 模式需要，16 字节)
        """
        if len(key) != 16:
            raise ValueError("SM4 key must be 16 bytes")
        
        self.key = key
        self.mode = mode.upper()
        self.iv = iv if iv else b'\x00' * 16
        
        if self.mode in ('CBC', 'CFB', 'OFB', 'CTR') and not iv:
            raise ValueError(f"{mode} mode requires IV")
        
        self.sm4 = sm4.CryptSM4()
        self.sm4.set_key(self.key)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        加密
        :param plaintext: 明文 (会自动 PKCS7 填充)
        :return: 密文
        """
        # PKCS7 填充
        padded = self._pkcs7_pad(plaintext)
        
        if self.mode == 'ECB':
            return self._encrypt_ecb(padded)
        elif self.mode == 'CBC':
            return self._encrypt_cbc(padded)
        elif self.mode == 'CTR':
            return self._encrypt_ctr(plaintext)  # CTR 不需要填充
        elif self.mode == 'CFB':
            return self._encrypt_cfb(plaintext)  # CFB 不需要填充
        elif self.mode == 'OFB':
            return self._encrypt_ofb(plaintext)  # OFB 不需要填充
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        解密
        :param ciphertext: 密文
        :return: 明文 (会自动移除 PKCS7 填充)
        """
        if self.mode == 'ECB':
            padded = self._decrypt_ecb(ciphertext)
        elif self.mode == 'CBC':
            padded = self._decrypt_cbc(ciphertext)
        elif self.mode == 'CTR':
            return self._decrypt_ctr(ciphertext)  # CTR 不需要去填充
        elif self.mode == 'CFB':
            return self._decrypt_cfb(ciphertext)  # CFB 不需要去填充
        elif self.mode == 'OFB':
            return self._decrypt_ofb(ciphertext)  # OFB 不需要去填充
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
        
        return self._pkcs7_unpad(padded)
    
    def _pkcs7_pad(self, data: bytes) -> bytes:
        """PKCS7 填充"""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)
    
    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """移除 PKCS7 填充"""
        pad_len = data[-1]
        return data[:-pad_len]
    
    def _encrypt_ecb(self, plaintext: bytes) -> bytes:
        """ECB 模式加密"""
        ciphertext = b''
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            ciphertext += self.sm4.encrypt_ecb(block)
        return ciphertext
    
    def _decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """ECB 模式解密"""
        plaintext = b''
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            plaintext += self.sm4.decrypt_ecb(block)
        return plaintext
    
    def _encrypt_cbc(self, plaintext: bytes) -> bytes:
        """CBC 模式加密"""
        ciphertext = b''
        prev_block = self.iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            # XOR with previous ciphertext block
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            encrypted = self.sm4.encrypt_ecb(xored)
            ciphertext += encrypted
            prev_block = encrypted
        return ciphertext
    
    def _decrypt_cbc(self, ciphertext: bytes) -> bytes:
        """CBC 模式解密"""
        plaintext = b''
        prev_block = self.iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted = self.sm4.decrypt_ecb(block)
            # XOR with previous ciphertext block
            xored = bytes(a ^ b for a, b in zip(decrypted, prev_block))
            plaintext += xored
            prev_block = block
        return plaintext
    
    def _encrypt_ctr(self, plaintext: bytes) -> bytes:
        """CTR 模式加密"""
        ciphertext = b''
        counter = self.iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            # Encrypt counter
            encrypted_counter = self.sm4.encrypt_ecb(counter)
            # XOR with plaintext
            xored = bytes(a ^ b for a, b in zip(block, encrypted_counter[:len(block)]))
            ciphertext += xored
            # Increment counter
            counter = self._increment_counter(counter)
        return ciphertext
    
    def _decrypt_ctr(self, ciphertext: bytes) -> bytes:
        """CTR 模式解密 (与加密相同)"""
        return self._encrypt_ctr(ciphertext)
    
    def _encrypt_cfb(self, plaintext: bytes) -> bytes:
        """CFB 模式加密"""
        ciphertext = b''
        prev_block = self.iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            # Encrypt previous ciphertext block
            encrypted = self.sm4.encrypt_ecb(prev_block)
            # XOR with plaintext
            xored = bytes(a ^ b for a, b in zip(block, encrypted[:len(block)]))
            ciphertext += xored
            prev_block = xored
        return ciphertext
    
    def _decrypt_cfb(self, ciphertext: bytes) -> bytes:
        """CFB 模式解密"""
        plaintext = b''
        prev_block = self.iv
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            # Encrypt previous ciphertext block
            encrypted = self.sm4.encrypt_ecb(prev_block)
            # XOR with ciphertext
            xored = bytes(a ^ b for a, b in zip(block, encrypted[:len(block)]))
            plaintext += xored
            prev_block = block
        return plaintext
    
    def _encrypt_ofb(self, plaintext: bytes) -> bytes:
        """OFB 模式加密"""
        ciphertext = b''
        prev_block = self.iv
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            # Encrypt previous block
            encrypted = self.sm4.encrypt_ecb(prev_block)
            # XOR with plaintext
            xored = bytes(a ^ b for a, b in zip(block, encrypted[:len(block)]))
            ciphertext += xored
            prev_block = encrypted
        return ciphertext
    
    def _decrypt_ofb(self, ciphertext: bytes) -> bytes:
        """OFB 模式解密 (与加密相同)"""
        return self._encrypt_ofb(ciphertext)
    
    def _increment_counter(self, counter: bytes) -> bytes:
        """增加计数器"""
        counter_list = list(counter)
        for i in range(len(counter_list) - 1, -1, -1):
            counter_list[i] = (counter_list[i] + 1) % 256
            if counter_list[i] != 0:
                break
        return bytes(counter_list)

# 便捷函数
def encrypt(plaintext: bytes, key: bytes, mode: str = 'CBC', iv: Optional[bytes] = None) -> bytes:
    """SM4 加密"""
    util = SM4Util(key, mode, iv)
    return util.encrypt(plaintext)

def decrypt(ciphertext: bytes, key: bytes, mode: str = 'CBC', iv: Optional[bytes] = None) -> bytes:
    """SM4 解密"""
    util = SM4Util(key, mode, iv)
    return util.decrypt(ciphertext)