import sys
sys.path.insert(0, 'crossmool/src')
from sm4_util import SM4Util

key = SM4Util.generate_key()
hex_key = SM4Util.generate_key_hex()
print(f'Key (HEX): {hex_key}')

plain_text = 'Hello, 這是国密SM4測試數據'
print(f'Plaintext: {plain_text}')

encrypted = SM4Util.encrypt_gcm_string(key, plain_text)
print(f'Encrypted (Base64): {encrypted}')

decrypted = SM4Util.decrypt_gcm_to_string(key, encrypted)
print(f'Decrypted: {decrypted}')

assert decrypted == plain_text, 'Decryption failed!'

# 防篡改测试
print('\nTamper test:')
tampered = encrypted[:-2] + 'XX'
try:
    SM4Util.decrypt_gcm_to_string(key, tampered)
    print('FAIL: Tampered data was accepted!')
except ValueError as e:
    print(f'PASS: Tampered data rejected: {e}')

print('\nGCM test passed!')
