const { SM2Util, SM3Util, SM4Util, hexToBytes, bytesToHex } = require("G:/workspaces/git/corssmool/crossmool/javascript/crossmool/dist/index.js");
const MSG = "Hello, 这是跨语言国密互通性测试数据";
const SM4_KEY = "0123456789abcdeffedcba9876543210";
const HMAC_KEY = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const EXP_SM3 = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b";
const EXP_SM3_HMAC = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";
const DK = {"enc_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "enc_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sig_pub_der_hex": "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sig_priv_der_hex": "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"};
const r = { lang: "javascript" };

try {
    const c = SM2Util.encrypt(MSG, DK.enc_pub_der_hex, false);
    r.sm2_enc = c;
    const d = SM2Util.decrypt(c, DK.enc_priv_der_hex);
    r.sm2_enc_dec = (d === MSG) ? "PASS" : "FAIL";
} catch(e) { r.sm2_enc_dec = "FAIL: " + e.message; }

try {
    const sig = SM2Util.sign(MSG, DK.sig_priv_der_hex, false);
    r.sm2_sig = sig;
    const ok = SM2Util.verify(MSG, DK.sig_pub_der_hex, sig);
    r.sm2_sig_ver = ok ? "PASS" : "FAIL";
} catch(e) { r.sm2_sig_ver = "FAIL: " + e.message; }

try {
    r.sm3_hash = SM3Util.digestToHex(MSG);
    r.sm3_ok = (r.sm3_hash === EXP_SM3);
} catch(e) { r.sm3_ok = "FAIL: " + e.message; }

try {
    const hm = SM3Util.hmac(hexToBytes(HMAC_KEY), MSG, false);
    r.sm3_hmac_hash = hm;
    r.sm3_hmac_ok = (hm === EXP_SM3_HMAC);
} catch(e) { r.sm3_hmac_ok = "FAIL: " + e.message; }

try {
    const sm4Key = hexToBytes(SM4_KEY);
    const sc = SM4Util.encryptGcmString(MSG, sm4Key, undefined, false);
    r.sm4_enc = sc;
    const sd = SM4Util.decryptGcmToString(sc, sm4Key);
    r.sm4_enc_dec = (sd === MSG) ? "PASS" : "FAIL";
} catch(e) { r.sm4_enc_dec = "FAIL: " + e.message; }

r.cross = { lang:"javascript", msg:MSG, sm2_enc:r.sm2_enc||"", sm2_sig:r.sm2_sig||"", sm4_enc:r.sm4_enc||"", sm3_hash:r.sm3_hash||"", sm3_hmac_hash:r.sm3_hmac_hash||"" };
console.log(JSON.stringify(r));