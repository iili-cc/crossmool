#!/usr/bin/env python3
from binascii import unhexlify

pub_hex = '3059301306072a8648ce3d020106082a811ccf5501822d034200042d3cdd809db791c70eb6594f56df07260f8164a153f3e10d8a30914a8365e141f7d097b1d6105aa5d33629da8c38816ec7399b591f3a3962b204e6b2e3de513c'
pub_bytes = unhexlify(pub_hex)
print('DER bytes:', pub_bytes.hex())
print('Length:', len(pub_bytes))

# Find 03 42 00
idx = pub_bytes.find(b'\x03\x42\x00')
print('Found 03 42 00 at:', idx)
if idx >= 0:
    raw_pub = pub_bytes[idx+3:idx+3+65]
    print('Raw public key:', raw_pub.hex())
    print('Starts with 04:', raw_pub[0] == 0x04)
    print('Without 04:', raw_pub[1:].hex())