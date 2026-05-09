#!/usr/bin/env python3
from gmssl.sm2 import CryptSM2
from binascii import unhexlify
import json

# Load test data
with open('test_data.json', 'r') as f:
    data = json.load(f)

pub_hex = data['sm2_public_key']
priv_hex = data['sm2_private_key']
cipher_hex = data['sm2_ciphertext']
signature_hex = data['sm2_signature']
message = data['test_message']

print(f"Message: {message}")
print(f"Public key: {pub_hex[:64]}...")
print(f"Private key: {priv_hex[:64]}...")
print(f"Ciphertext: {cipher_hex[:64]}...")
print(f"Signature: {signature_hex[:64]}...")

pub_bytes = unhexlify(pub_hex)
priv_bytes = unhexlify(priv_hex)

# Extract raw keys
# Public key: find 03 42 00
pub_idx = pub_bytes.find(b'\x03\x42\x00')
raw_pub = pub_bytes[pub_idx+3:pub_idx+3+65] if pub_idx >= 0 else None
print(f"\nRaw public key: {raw_pub.hex() if raw_pub else 'None'}")
print(f"Raw public key (without 04): {raw_pub[1:].hex() if raw_pub else 'None'}")

# Private key: find 04 20
priv_idx = priv_bytes.find(b'\x04\x20')
raw_priv = priv_bytes[priv_idx+2:priv_idx+2+32] if priv_idx >= 0 else None
print(f"Raw private key: {raw_priv.hex() if raw_priv else 'None'}")

# Create CryptSM2
pub_key = raw_pub[1:].hex() if raw_pub else None
priv_key = raw_priv.hex() if raw_priv else None

print(f"\nUsing public key: {pub_key}")
print(f"Using private key: {priv_key}")

sm2_crypt = CryptSM2(private_key=priv_key, public_key=pub_key, mode=1)

# Test decrypt
# Java outputs: 04 || x || y || C3 || C2
# gmssl expects: x || y || C3 || C2 (without 04 prefix)
print(f"\n=== Test Decrypt ===")
cipher_bytes = unhexlify(cipher_hex)
print(f"Original cipher length: {len(cipher_bytes)} bytes")
print(f"First byte: 0x{cipher_bytes[0]:02x}")

# Remove 04 prefix for gmssl
if cipher_bytes[0] == 0x04:
    cipher_bytes_no_prefix = cipher_bytes[1:]
    print(f"Cipher without 04 prefix: {len(cipher_bytes_no_prefix)} bytes")
else:
    cipher_bytes_no_prefix = cipher_bytes

decrypted = sm2_crypt.decrypt(cipher_bytes_no_prefix)
print(f"Decrypted hex: {decrypted.hex() if decrypted else 'None'}")
if decrypted:
    try:
        decrypted_text = decrypted.decode('utf-8')
        print(f"Decrypted text: {decrypted_text}")
        print(f"Expected: {message}")
        print(f"Match: {decrypted_text == message}")
    except Exception as e:
        print(f"Decode error: {e}")

# Test verify
print(f"\n=== Test Verify ===")
sm2_verify = CryptSM2(private_key=None, public_key=pub_key, mode=1, asn1=True)
msg_bytes = message.encode('utf-8')
result = sm2_verify.verify_with_sm3(signature_hex, msg_bytes)
print(f"Verify result: {result}")
print(f"Expected: True")