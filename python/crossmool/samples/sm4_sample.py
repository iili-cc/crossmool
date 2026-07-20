"""
SM4 国密对称加密算法示例（GCM 模式）

快速上手：
  1. cd python/crossmool
  2. pip install -e .
  3. python samples/sm4_sample.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sm4_util import SM4Util


def main():
    print("=" * 60)
    print("  SM4 Sample — 国密对称加密 (GCM 模式)")
    print("=" * 60)
    print()

    original_content = (
        "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。"
        "路过咖啡店时買了一杯美式，順便（顺便）看了下手机，"
        "今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。"
        "朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" "
        "我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。"
    )
    print(f"OriginalContent ::: {original_content}")
    print()

    print(">>> 1. 生成 SM4 密钥（128-bit）")
    hex_key = SM4Util.generate_key_hex()
    base64_key = SM4Util.generate_key_base64()
    print(f"  SM4 Hex Key    ::: {hex_key}")
    print(f"  SM4 Base64 Key ::: {base64_key}")
    print()

    key_bytes = SM4Util.parse_hex_key(hex_key)

    print(">>> 2. 使用 Hex 密钥进行 GCM 加解密")
    encrypted_hex = SM4Util.encrypt_gcm_string(key_bytes, original_content)
    print(f"  Encrypted (Hex) ::: {encrypted_hex[:150]}...")

    decrypted_hex = SM4Util.decrypt_gcm_to_string(key_bytes, encrypted_hex)
    print(f"  Decrypted (Hex) ::: {decrypted_hex}")
    print(f"  WhetherDecryptEqualsOriginalContent (Hex) ::: {original_content == decrypted_hex}")
    print()

    print(">>> 3. 使用 Base64 输出进行 GCM 加解密")
    encrypted_b64 = SM4Util.encrypt_gcm_string(key_bytes, original_content, to_base64=True)
    print(f"  Encrypted (Base64) ::: {encrypted_b64[:100]}...")

    decrypted_b64 = SM4Util.decrypt_gcm_to_string(key_bytes, encrypted_b64)
    print(f"  Decrypted (Base64) ::: {decrypted_b64}")
    print(f"  WhetherDecryptEqualsOriginalContent (Base64) ::: {original_content == decrypted_b64}")
    print()

    print(">>> 4. 随机 IV 验证（每次 GCM 加密密文不同）")
    ct1 = SM4Util.encrypt_gcm_string(key_bytes, "Same plaintext")
    ct2 = SM4Util.encrypt_gcm_string(key_bytes, "Same plaintext")
    print(f"  Ciphertext 1 ::: {ct1[:50]}...")
    print(f"  Ciphertext 2 ::: {ct2[:50]}...")
    print(f"  IV differs (ciphertexts not equal) ::: {ct1 != ct2}")
    print()

    print(">>> 5. GCM 防篡改验证")
    print("  （故意篡改密文末尾字符，GCM 应检测到并拒绝解密）")
    tampered = encrypted_hex[:-2] + "XX"
    try:
        hacked = SM4Util.decrypt_gcm_to_string(key_bytes, tampered)
        print(f"  Tampered decrypted ::: {hacked}")
    except Exception as ex:
        print(f"  GCM detected tampering, decryption failed ::: {ex}")
    print()

    print("=== SM4 Sample 完成 ===")


if __name__ == "__main__":
    main()
