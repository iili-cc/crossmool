"""
SM2 国密非对称加密算法示例

快速上手：
  1. cd python/crossmool
  2. pip install -e .
  3. python samples/sm2_sample.py

核心能力：
  - 生成 SM2 密钥对（Hex / Base64）
  - 公钥加密 → 私钥解密
  - 私钥签名 → 公钥验签
  - 先加密再签名 → 先验签再解密（防篡改 + 防抵赖）
  - PEM 格式导入导出
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sm2_util import SM2Util


def main():
    print("=" * 60)
    print("  SM2 Sample — 国密非对称加密 (SM2P256V1)")
    print("=" * 60)
    print()

    original_content = (
        "今天天气真好，气温大约 28°C，我决定出門走走。"
        "路过咖啡店时買了一杯美式，順便（顺便）看了下手机。"
        "Don't forget to bring your umbrella!"
    )
    print(f"OriginalContent ::: {original_content}")
    print()

    print(">>> 1. 生成两对 SM2 密钥（第1对加解密，第2对签名）")
    kp1 = SM2Util.generate_keypair_hex()
    kp2 = SM2Util.generate_keypair_hex()
    pub1, pri1 = kp1["publicKey"], kp1["privateKey"]
    pub2, pri2 = kp2["publicKey"], kp2["privateKey"]

    print(f"  privateKeyHex-1 ::: {pri1}")
    print(f"  publicKeyHex-1  ::: {pub1}")
    print(f"  privateKeyHex-2 ::: {pri2}")
    print(f"  publicKeyHex-2  ::: {pub2}")
    print()

    print(">>> 2. 加密并签名 → 验签并解密（先加密再签名，先验签再解密）")
    pair = SM2Util.encrypt_sign(original_content, pub1, pri2)
    ct, sig = pair["ciphertext"], pair["signature"]
    print(f"  CipherText ::: {ct[:150]}...")
    print(f"  Signature  ::: {sig}")
    print()

    verify_decrypt = SM2Util.verify_decrypt(ct, sig, pub2, pri1)
    print(f"  VerifyDecrypt ::: {verify_decrypt}")
    print(f"  WhetherVerifyDecryptEqualsOriginalContent ::: {original_content == verify_decrypt}")
    print()

    print(">>> 3. 公钥加密 → 私钥解密")
    encrypted = SM2Util.encrypt(original_content, pub1)
    print(f"  EncryptedContent ::: {encrypted[:150]}...")

    decrypted = SM2Util.decrypt(encrypted, pri1)
    print(f"  DecryptedContent ::: {decrypted}")
    print(f"  WhetherDecryptEqualsOriginalContent ::: {original_content == decrypted}")
    print()

    print(">>> 4. 私钥签名 → 公钥验签")
    sig_hex = SM2Util.sign(original_content, pri2)
    print(f"  ContentSignature ::: {sig_hex}")

    verify_ok = SM2Util.verify_str(original_content, pub2, sig_hex)
    print(f"  WhetherVerifyEqualsOriginalContent ::: {verify_ok}")
    print()

    print(">>> 5. Base64 格式输出（可选）")
    encrypted_b64 = SM2Util.encrypt(original_content, pub1, to_base64=True)
    print(f"  Encrypted (Base64) ::: {encrypted_b64[:100]}...")

    sig_b64 = SM2Util.sign(original_content, pri2, to_base64=True)
    print(f"  Signature  (Base64) ::: {sig_b64}")
    print()

    print(">>> 6. PEM 格式（跨语言密钥交换）")
    kp_raw = SM2Util.generate_keypair_hex()
    pub_pem = SM2Util.export_public_key_pem(kp_raw["publicKey"])
    pri_pem = SM2Util.export_private_key_pem(kp_raw["privateKey"], kp_raw["publicKey"])
    print(f"  Public Key PEM:\n{pub_pem}")
    print(f"  Private Key PEM:\n{pri_pem}")

    imported_pub = SM2Util.import_public_key_pem(pub_pem)
    print(f"  PEM Roundtrip ::: {imported_pub == kp_raw['publicKey']}")
    print()

    print("=== SM2 Sample 完成 ===")


if __name__ == "__main__":
    main()
