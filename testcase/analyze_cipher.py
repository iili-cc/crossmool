#!/usr/bin/env python3
from binascii import unhexlify
import json

# Load test data
with open('test_data.json', 'r') as f:
    data = json.load(f)

cipher_hex = data['sm2_ciphertext']
message = data['test_message']

print(f"Ciphertext hex: {cipher_hex}")
print(f"Ciphertext length: {len(cipher_hex)} chars = {len(cipher_hex)//2} bytes")
print(f"Message: {message}")
print(f"Message length: {len(message)} bytes")

cipher_bytes = unhexlify(cipher_hex)

# Java BouncyCastle SM2Engine C1C3C2 format:
# 04 || x[32] || y[32] || C3[32] || C2[N]
# Total: 1 + 32 + 32 + 32 + N = 97 + N bytes

print(f"\n=== Analyze Java Ciphertext Format ===")
print(f"First byte: 0x{cipher_bytes[0]:02x} (should be 04 for uncompressed point)")
print(f"C1 (public point): {cipher_bytes[0:65].hex()}")
print(f"  Length: {len(cipher_bytes[0:65])} bytes")

# After C1, we have C3 || C2
# C3 is 32 bytes (SM3 hash)
# C2 is the encrypted data

# gmssl expects: C1 || C3 || C2 where C1 is 64 hex chars (32 bytes without 04)
# But Java outputs: 04 || x || y || C3 || C2

# Let's check the structure
c1_with_prefix = cipher_bytes[0:65]
remaining = cipher_bytes[65:]
print(f"\nRemaining after C1: {len(remaining)} bytes")
print(f"Remaining hex: {remaining.hex()}")

# The remaining should be C3 (32 bytes) || C2 (encrypted data)
c3 = remaining[0:32]
c2 = remaining[32:]
print(f"\nC3 (hash): {c3.hex()}")
print(f"C2 (encrypted): {c2.hex()}")
print(f"C2 length: {len(c2)} bytes (message is {len(message)} bytes, so padding is {len(c2) - len(message)} bytes)")

# gmssl decrypt expects the format as-is (C1C3C2)
# Let's check if gmssl mode=1 is correct
print(f"\n=== gmssl format check ===")
print(f"gmssl mode=1 expects: C1 || C3 || C2")
print(f"  C1: 64 hex chars (32 bytes, no 04 prefix)")
print(f"  C3: 64 hex chars (32 bytes)")
print(f"  C2: variable")
print(f"\nJava outputs: 04 || x || y || C3 || C2")
print(f"  Total C1 with prefix: 65 bytes")
print(f"  This should work with gmssl mode=1")