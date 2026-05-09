#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Debug SM4 ECB encryption to find the bug
"""
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT, PKCS7
from gmssl.func import pkcs7_padding, pkcs7_unpadding, bytes_to_list, list_to_bytes

def test_sm4_ecb():
    print("SM4 ECB Debug Test")
    print("=" * 50)
    
    # Test data
    key = b'0123456789abcdef'  # 16 bytes
    plaintext = b'Hello, SM4 ECB Test! This is a test message.'  # 48 bytes
    
    print(f"Key (hex): {key.hex()}")
    print(f"Key length: {len(key)} bytes")
    print(f"Plaintext: {plaintext}")
    print(f"Plaintext length: {len(plaintext)} bytes")
    print()
    
    # Test PKCS7 padding
    plaintext_padded = pkcs7_padding(bytes_to_list(plaintext))
    print(f"After PKCS7 padding: {len(plaintext_padded)} bytes")
    print(f"Padded data (hex): {bytes(plaintext_padded).hex()}")
    print(f"Last 16 bytes: {bytes(plaintext_padded[-16:])}")
    print()
    
    # Encrypt
    sm4 = CryptSM4(SM4_ENCRYPT, PKCS7)
    sm4.set_key(key, SM4_ENCRYPT)
    ciphertext = sm4.crypt_ecb(plaintext)
    
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print()
    
    # Expected: 48 bytes input -> 64 bytes output (3 blocks -> 4 blocks with padding)
    # This is CORRECT PKCS7 behavior!
    
    # Now test decryption
    print("Testing decryption...")
    sm4_decrypt = CryptSM4(SM4_DECRYPT, PKCS7)
    sm4_decrypt.set_key(key, SM4_DECRYPT)
    decrypted = sm4_decrypt.crypt_ecb(ciphertext)
    
    print(f"Decrypted: {decrypted}")
    print(f"Decrypted length: {len(decrypted)} bytes")
    print(f"Match: {decrypted == plaintext}")
    print()
    
    # Test with 16-byte input (exactly one block)
    print("=" * 50)
    print("Test with 16-byte input (exactly one block):")
    plaintext_16 = b'16 bytes message'  # Exactly 16 bytes
    print(f"Plaintext: {plaintext_16}")
    print(f"Plaintext length: {len(plaintext_16)} bytes")
    
    ciphertext_16 = sm4.crypt_ecb(plaintext_16)
    print(f"Ciphertext length: {len(ciphertext_16)} bytes")
    print(f"Ciphertext (hex): {ciphertext_16.hex()}")
    
    decrypted_16 = sm4_decrypt.crypt_ecb(ciphertext_16)
    print(f"Decrypted: {decrypted_16}")
    print(f"Match: {decrypted_16 == plaintext_16}")
    print()
    
    # Test with 15-byte input (needs 1 byte padding)
    print("=" * 50)
    print("Test with 15-byte input (needs 1 byte padding):")
    plaintext_15 = b'15 bytes msg'  # 15 bytes
    print(f"Plaintext: {plaintext_15}")
    print(f"Plaintext length: {len(plaintext_15)} bytes")
    
    ciphertext_15 = sm4.crypt_ecb(plaintext_15)
    print(f"Ciphertext length: {len(ciphertext_15)} bytes")
    print(f"Ciphertext (hex): {ciphertext_15.hex()}")
    
    decrypted_15 = sm4_decrypt.crypt_ecb(ciphertext_15)
    print(f"Decrypted: {decrypted_15}")
    print(f"Match: {decrypted_15 == plaintext_15}")

if __name__ == '__main__':
    test_sm4_ecb()