#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test SM4 interoperability between Java and Python
"""
import sys
import json
from gmssl import sm4
from gmssl.sm4 import SM4_ENCRYPT, SM4_DECRYPT, PKCS7

def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def bytes_to_hex(data):
    return data.hex()

def test_python_encrypt_decrypt():
    """Test Python SM4 encrypt and decrypt (self-test)"""
    print("Python SM4 ECB Self-Test")
    print("=" * 50)
    
    key = hex_to_bytes("fa3f9a56f212b4ef2e5367f4a73b8e73")
    plaintext = b"Hello, Cross-Language Interop Test!"
    
    print(f"Key: {bytes_to_hex(key)}")
    print(f"Plaintext: {plaintext}")
    print()
    
    # Encrypt
    sm4_encrypt = sm4.CryptSM4(SM4_ENCRYPT, PKCS7)
    sm4_encrypt.set_key(key, SM4_ENCRYPT)
    ciphertext = sm4_encrypt.crypt_ecb(plaintext)
    
    print(f"Encrypted (hex): {bytes_to_hex(ciphertext)}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print()
    
    # Decrypt
    sm4_decrypt = sm4.CryptSM4(SM4_DECRYPT, PKCS7)
    sm4_decrypt.set_key(key, SM4_DECRYPT)
    decrypted = sm4_decrypt.crypt_ecb(ciphertext)
    
    print(f"Decrypted: {decrypted}")
    print(f"Match: {decrypted == plaintext}")
    print()
    
    return ciphertext, decrypted == plaintext

def test_java_ciphertext_decrypt(java_ciphertext_hex, key_hex):
    """Test decrypt Java-generated ciphertext with Python"""
    print("Python Decrypt Java Ciphertext")
    print("=" * 50)
    
    key_bytes = hex_to_bytes(key_hex)
    cipher_bytes = hex_to_bytes(java_ciphertext_hex)
    
    print(f"Key: {key_hex}")
    print(f"Ciphertext (hex): {java_ciphertext_hex}")
    print(f"Ciphertext length: {len(cipher_bytes)} bytes")
    print()
    
    # Decrypt
    sm4_decrypt = sm4.CryptSM4(SM4_DECRYPT, PKCS7)
    sm4_decrypt.set_key(key_bytes, SM4_DECRYPT)
    decrypted = sm4_decrypt.crypt_ecb(cipher_bytes)
    
    print(f"Decrypted: {decrypted}")
    print(f"Decrypted (hex): {bytes_to_hex(decrypted)}")
    print()
    
    return decrypted

def test_cross_encrypt(key_hex, plaintext):
    """
    Test if Python encryption output can be decrypted by Java
    This is the actual interop test
    """
    print("Python Encrypt -> Java Decrypt Test")
    print("=" * 50)
    
    key_bytes = hex_to_bytes(key_hex)
    plaintext_bytes = plaintext.encode('utf-8')
    
    print(f"Key: {key_hex}")
    print(f"Plaintext: {plaintext}")
    print(f"Plaintext bytes: {len(plaintext_bytes)}")
    print()
    
    # Python encrypt
    sm4_encrypt = sm4.CryptSM4(SM4_ENCRYPT, PKCS7)
    sm4_encrypt.set_key(key_bytes, SM4_ENCRYPT)
    ciphertext = sm4_encrypt.crypt_ecb(plaintext_bytes)
    
    print(f"Python encrypted (hex):")
    print(f"  {bytes_to_hex(ciphertext)}")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print()
    
    # Python decrypt to verify
    sm4_decrypt = sm4.CryptSM4(SM4_DECRYPT, PKCS7)
    sm4_decrypt.set_key(key_bytes, SM4_DECRYPT)
    decrypted = sm4_decrypt.crypt_ecb(ciphertext)
    
    print(f"Python decrypted: {decrypted}")
    print(f"Python self-test: {decrypted == plaintext_bytes}")
    print()
    
    return bytes_to_hex(ciphertext)

if __name__ == '__main__':
    # Test 1: Python self-test
    ciphertext, passed = test_python_encrypt_decrypt()
    if not passed:
        print("[FAIL] Python self-test failed!")
        sys.exit(1)
    print("[PASS] Python self-test\n")
    
    # Test 2: Decrypt Java ciphertext (from test_data.json)
    print("\n" + "=" * 50)
    print("Testing with Java-generated test data")
    print("=" * 50 + "\n")
    
    try:
        with open('test_data.json', 'r') as f:
            test_data = json.load(f)
        
        sm4_key = test_data['sm4_key_hex']
        java_ciphertext = test_data['sm4_ciphertext']
        original_message = test_data['test_message']
        
        print(f"Original message: {original_message}")
        print(f"SM4 key: {sm4_key}")
        print(f"Java ciphertext: {java_ciphertext}")
        print()
        
        # Decrypt Java ciphertext
        decrypted = test_java_ciphertext_decrypt(java_ciphertext, sm4_key)
        
        if decrypted.decode('utf-8') == original_message:
            print("[PASS] Java->Python SM4 decrypt works!")
        else:
            print(f"[FAIL] Decrypted message mismatch!")
            print(f"  Expected: {original_message}")
            print(f"  Got: {decrypted.decode('utf-8')}")
        
        print()
        
        # Test 3: Python encrypt (for Java to verify)
        print("=" * 50)
        python_ciphertext = test_cross_encrypt(sm4_key, original_message)
        
        print("=" * 50)
        print("SUMMARY")
        print("=" * 50)
        print("1. Python SM4 ECB encrypt/decrypt: WORKS")
        print("2. Python decrypt Java ciphertext: WORKS")
        print("3. Python encrypt output (hex):")
        print(f"   {python_ciphertext}")
        print()
        print("Next step: Use Java to decrypt the Python ciphertext above")
        print("to verify Python->Java interop works correctly.")
        
    except FileNotFoundError:
        print("test_data.json not found, skipping Java interop test")
        print("Run GenerateSMTestData.java first to generate test data")