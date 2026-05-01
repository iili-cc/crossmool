#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crossmool Python - 国密算法实现
"""

from .sm2 import SM2Util, SM2KeyUtil, encrypt, decrypt, sign, verify
from .sm3 import sm3_hash, sm3_hash_hex, sm3_kdf
from .sm4 import SM4Util, encrypt as sm4_encrypt, decrypt as sm4_decrypt

__all__ = [
    # SM2
    'SM2Util',
    'SM2KeyUtil',
    'encrypt',
    'decrypt',
    'sign',
    'verify',
    # SM3
    'sm3_hash',
    'sm3_hash_hex',
    'sm3_kdf',
    # SM4
    'SM4Util',
    'sm4_encrypt',
    'sm4_decrypt',
]

__version__ = '1.0.0'