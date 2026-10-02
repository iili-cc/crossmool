"""
SM3 hash algorithm sample.

Quick start:
  1. cd python/crossmool
  2. pip install -e .
  3. python samples/sm3_sample.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from crossmool import SM3Util


def main():
    print("=" * 60)
    print("  SM3 Sample — 国密哈希算法 (256-bit)")
    print("=" * 60)
    print()

    print(">>> 1. SM3 消息摘要 (Digest)")
    input_str = (
        "在这个全球化时代，無論身處何地，"
        "learning and growth are always the keys to a fulfilling life."
    )
    print(f"  Input        ::: {input_str}")

    hash_val = SM3Util.digest_str(input_str)
    print(f"  SM3 Hash     ::: {hash_val}")
    print(f"  SM3 Hash (Hex) ::: {SM3Util.digest_str(input_str, to_base64=False)}")
    print(f"  Whether Hash Equals Hex ::: {hash_val == SM3Util.digest_str(input_str)}")
    print()

    print(">>> 2. HMAC-SM3 消息认证码")
    hmac_key = SM3Util.generate_hmac_key_to_str()
    print(f"  HMAC Key      ::: {hmac_key}")

    hmac_val = SM3Util.hmac_str(input_str, hmac_key)
    print(f"  HMAC Value    ::: {hmac_val}")
    hmac_val2 = SM3Util.hmac_str(input_str, hmac_key)
    print(f"  HMAC Value 2  ::: {hmac_val2}")
    print(f"  Whether HMAC Values Equal ::: {hmac_val == hmac_val2}")
    print()

    print(">>> 3. HMAC 校验（防篡改验证）")
    print(f"  HMAC Verify (correct)   ::: {SM3Util.hmac_verify(input_str, hmac_key, hmac_val)}")
    print(f"  HMAC Verify (tampered)  ::: {SM3Util.hmac_verify(input_str + 'X', hmac_key, hmac_val)}")
    print()

    print(">>> 4. 字节数组摘要（非字符串场景）")
    data = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
    digest_hex = SM3Util.digest_to_hex(data)
    print(f"  Input (5 bytes): {' '.join(f'{b:02x}' for b in data)}")
    print(f"  Digest (HEX)  : {digest_hex}")
    print()

    print(">>> 5. Base64 格式输出（可选）")
    print(f"  SM3 Hash (Base64) ::: {SM3Util.digest_str(input_str, to_base64=True)}")
    print(f"  HMAC Key (Base64) ::: {SM3Util.generate_hmac_key_to_str(32, to_base64=True)}")
    print()

    print("=== SM3 Sample 完成 ===")


if __name__ == "__main__":
    main()
