import json, sys, os
sys.path.insert(0, r"G:\\workspaces\\git\\corssmool\\crossmool\python\crossmool\src")
from sm2_util import SM2Util
from sm3_util import SM3Util
from sm4_util import SM4Util
from encoding import bytes_to_hex

MSG = "Hello, 这是跨语言国密互通性测试数据"
DK = {"enc_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "enc_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sig_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sig_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "enc_pub_raw": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sig_pub_raw": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "enc_priv_raw": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", "sig_priv_raw": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3"}

def test():
    r = {"lang": "python"}

    # SM2 Enc/Dec
    try:
        c = SM2Util.encrypt(MSG, DK["enc_pub_der_hex"], to_base64=False)
        r["sm2_enc"] = c
        d = SM2Util.decrypt(c, DK["enc_priv_der_hex"])
        r["sm2_enc_dec"] = "PASS" if d == MSG else f"FAIL: got {d[:50]}..."
    except Exception as e:
        r["sm2_enc_dec"] = f"FAIL: {e}"

    # SM2 Sig/Ver
    try:
        sig = SM2Util.sign(MSG, DK["sig_priv_der_hex"], to_base64=False)
        r["sm2_sig"] = sig
        ok = SM2Util.verify(MSG, DK["sig_pub_der_hex"], sig)
        r["sm2_sig_ver"] = "PASS" if ok else "FAIL"
    except Exception as e:
        r["sm2_sig_ver"] = f"FAIL: {e}"

    # SM2 Encrypt+Sign / Verify+Decrypt
    try:
        from sm2_util import SM2Util as S
        pair = S.encrypt_sign(MSG, DK["enc_pub_der_hex"], DK["sig_priv_der_hex"])
        r["sm2_enc_sign"] = {"cipher": pair[0], "sig": pair[1]}
        dec = S.verify_decrypt(pair[0], pair[1], DK["sig_pub_der_hex"], DK["enc_priv_der_hex"])
        r["sm2_esvd"] = "PASS" if dec == MSG else f"FAIL: got {dec[:50]}..."
    except Exception as e:
        r["sm2_esvd"] = f"FAIL: {e}"

    # SM3
    try:
        h = SM3Util.digest_hex(MSG)
        r["sm3_hash"] = h
        r["sm3_ok"] = (h == "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b")
    except Exception as e:
        r["sm3_ok"] = f"FAIL: {e}"

    # SM3-HMAC
    try:
        import binascii
        hmackey = binascii.unhexlify("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
        hh = SM3Util.hmac_hex(hmackey, MSG)
        r["sm3_hmac_hash"] = hh
        r["sm3_hmac_ok"] = (hh == "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6")
    except Exception as e:
        r["sm3_hmac_ok"] = f"FAIL: {e}"

    # SM4
    try:
        import binascii
        sm4key = binascii.unhexlify("0123456789abcdeffedcba9876543210")
        sc = SM4Util.encrypt_gcm(sm4key, MSG.encode("utf-8"), to_base64=False)
        r["sm4_enc"] = sc
        sd = SM4Util.decrypt_gcm_to_string(sm4key, sc)
        r["sm4_enc_dec"] = "PASS" if sd == MSG else "FAIL"
    except Exception as e:
        r["sm4_enc_dec"] = f"FAIL: {e}"

    return r

if __name__ == "__main__":
    import json
    result = test()
    # For cross-language: produce reference data
    if len(sys.argv) > 1 and sys.argv[1] == "--cross-data":
        cd = {
            "msg": MSG,
            "sm2_enc": result.get("sm2_enc", ""),
            "sm2_sig": result.get("sm2_sig", ""),
            "sm2_enc_sign": result.get("sm2_enc_sign", ""),
            "sm4_enc": result.get("sm4_enc", ""),
            "sm3_hash": result.get("sm3_hash", ""),
            "sm3_hmac_hash": result.get("sm3_hmac_hash", ""),
        }
        print(json.dumps(cd, ensure_ascii=False))
        return
    print(json.dumps(result, ensure_ascii=False))
