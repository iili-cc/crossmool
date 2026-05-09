"""
Test to verify Python output and generate correct Java key format
"""
import json
from gmssl import sm2, sm3, sm4, func
from gmssl.sm2 import CryptSM2
from gmssl import sm2, func
from gmssl.func import random_hex

# Test data
test_message = "Hello, Java-Python Interop Test!"
sm4_key_hex = "df87a629223dbbae37ed67dd0304643a"
hmac_key_hex = "4ae2b84dd8cef6a39602edfa66f07b9970c79ca86a9641f3de4b7217f08e186c"

# Generate SM2 keypair using ecdsa curve
print("Generating SM2 keypair...")
import secrets

# SM2 curve order
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
# Generator point (simplified - use hardcoded values from gmssl)
gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF

# Generate random private key
private_key_int = secrets.randbelow(n - 1) + 1
private_key_raw = private_key_int.to_bytes(32, 'big')

# Compute public key (simplified - just for demo, use precomputed for actual test)
# For actual test, use existing test data
print(f"Raw private key ({len(private_key_raw)} bytes): {private_key_raw.hex()}")

# For this test, let's use the test data from previous run
# Raw public key (64 bytes, no 04 prefix)
public_key_raw = bytes.fromhex("2d3cdd809db791c70eb6594f56df07260f8164a153f3e10d8a30914a8365e141f7d097b1d6105aa5d33629da8c38816ec7399b591f3a3962b204e6b2e3de513c")
private_key_raw = bytes.fromhex("6e8ca55e19d665cab47de098767705f1d625fda2333eaeb8bde73a324bd4a6be")

print(f"Using test keypair:")
print(f"  Raw private key (32 bytes): {private_key_raw.hex()}")
print(f"  Raw public key (64 bytes): {public_key_raw.hex()}")

# SM2 encrypt
print("\nSM2 Encrypt...")
crypt_sm2 = CryptSM2(private_key_raw.hex(), public_key_raw.hex(), mode=1)
ciphertext_raw = crypt_sm2.encrypt(test_message.encode('utf-8'))
print(f"Ciphertext ({len(ciphertext_raw)} bytes): {ciphertext_raw.hex()}")

# SM2 sign
print("\nSM2 Sign...")
crypt_sm2_sign = CryptSM2(private_key_raw.hex(), public_key_raw.hex(), mode=1)
signature = crypt_sm2_sign.sign_with_sm3(test_message.encode('utf-8'))
# signature is a hex string, convert to bytes
signature_bytes = bytes.fromhex(signature)
print(f"Signature ({len(signature_bytes)} bytes): {signature}")

# SM3
print("\nSM3 Hash...")
sm3_digest = sm3.sm3_hash(list(test_message.encode('utf-8')))
print(f"SM3 Digest: {sm3_digest}")

# HMAC-SM3
print("\nHMAC-SM3...")
hmac_key = bytes.fromhex(hmac_key_hex)

# Use standard hmac module with SM3 digest adapter
class SM3Digest:
    block_size = 64
    digest_size = 32
    
    def __init__(self, data=b''):
        self._data = data
    
    def update(self, data):
        self._data += data
    
    def digest(self):
        hash_hex = sm3.sm3_hash(list(self._data))
        return bytes.fromhex(hash_hex)
    
    def hexdigest(self):
        return self.digest().hex()
    
    def copy(self):
        return SM3Digest(self._data)

import hmac as hmac_lib
h = hmac_lib.new(hmac_key, test_message.encode('utf-8'), digestmod=SM3Digest)
hmac_result = h.hexdigest()
print(f"HMAC-SM3: {hmac_result}")

# SM4
print("\nSM4 Decrypt (Java ciphertext)...")
sm4_key = bytes.fromhex(sm4_key_hex)
java_sm4_ciphertext = bytes.fromhex("4423b3f31afd55be58f98ab9d9915e0b539302bfe6e49bb99624d082e74690046fe098053eae90e24ee26812136f4805")

from gmssl.sm4 import CryptSM4, SM4_DECRYPT
crypt_sm4 = CryptSM4()
crypt_sm4.set_key(sm4_key, SM4_DECRYPT)
decrypted = crypt_sm4.crypt_ecb(java_sm4_ciphertext)
print(f"Decrypted: {decrypted.decode('utf-8')}")

# Now construct DER formats for Java
print("\n=== Java Key Formats ===")

# Construct PKCS#8 private key for Java
# Format: 308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420{priv}a00a06082a811ccf5501822da14403420004{pub_raw}
# Note: pkcs8_middle already includes 04 prefix, so we just append public_key_raw (64 bytes x||y)
pkcs8_prefix = bytes.fromhex("308193020100301306072a8648ce3d020106082a811ccf5501822d047930770201010420")
pkcs8_middle = bytes.fromhex("a00a06082a811ccf5501822da14403420004")  # ends with 04 prefix
# pkcs8_middle already has 04, just append public_key_raw (64 bytes)
pkcs8_private_key = pkcs8_prefix + private_key_raw + pkcs8_middle + public_key_raw
print(f"PKCS#8 Private Key ({len(pkcs8_private_key)} bytes): {pkcs8_private_key.hex()}")

# Construct X.509 public key for Java
# Format: 3059301306072a8648ce3d020106082a811ccf5501822d03420004{pub}
x509_prefix = bytes.fromhex("3059301306072a8648ce3d020106082a811ccf5501822d03420004")
x509_public_key = x509_prefix + public_key_raw
print(f"X.509 Public Key ({len(x509_public_key)} bytes): {x509_public_key.hex()}")

# Verify signature
print("\n=== Signature Verification ===")
verify_result = crypt_sm2_sign.verify_with_sm3(signature, test_message.encode('utf-8'))
print(f"Signature verify result: {verify_result}")

# Verify decryption
print("\n=== Decryption Verification ===")
# Add 04 prefix for Java ciphertext format
ciphertext_with_prefix = bytes.fromhex("04") + ciphertext_raw
print(f"Ciphertext with 04 prefix: {ciphertext_with_prefix.hex()[:64]}...")
# Python decrypt expects raw format (no 04)
decrypted_msg = crypt_sm2.decrypt(ciphertext_raw)
print(f"Decrypted message: {decrypted_msg.decode('utf-8')}")

print("\n=== Summary ===")
print(f"Message: {test_message}")
print(f"SM3: {sm3_digest}")
print(f"HMAC-SM3: {hmac_result}")
print(f"SM2 Ciphertext (raw): {ciphertext_raw.hex()}")
print(f"SM2 Signature (DER): {signature}")
print(f"PKCS#8 Private Key: {pkcs8_private_key.hex()}")
print(f"X.509 Public Key: {x509_public_key.hex()}")
