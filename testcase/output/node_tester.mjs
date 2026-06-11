
const crypto = require('crypto');
const MSG = "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e";
const D = {"msg": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e", "sm2_enc_priv": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", "sm2_enc_pub": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sm2_sig_priv": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3", "sm2_sig_pub": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sm4_key": "0123456789abcdeffedcba9876543210", "sm4_iv": "000102030405060708090a0b", "hmac_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"};
const EXP = {"sm3": "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b", "sm3_hmac": "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"};
const PATH = "D:/workspaces/git/corssmool/crossmool/javascript/crossmool";

async function main() {
    // Try dynamic import first for ESM, fallback to require
    let SM2Util, SM3Util, SM4Util, encoding;
    try {
        const m = await import(PATH + "/dist/index.mjs");
        SM2Util = m.SM2Util; SM3Util = m.SM3Util; SM4Util = m.SM4Util;
        encoding = m;
    } catch(e) {
        try {
            const m = await import("file://" + PATH + "/dist/index.mjs");
            SM2Util = m.SM2Util; SM3Util = m.SM3Util; SM4Util = m.SM4Util;
        } catch(e2) {
            const m = require(PATH + "/dist/index.js");
            SM2Util = m.SM2Util; SM3Util = m.SM3Util; SM4Util = m.SM4Util;
        }
    }
    
    const r = {};
    // SM3
    r.sm3 = SM3Util.digest(MSG);
    r.sm3_ok = (r.sm3 === EXP.sm3);
    // SM3-HMAC
    r.sm3_hmac = SM3Util.hmac(D.hmac_key, MSG);
    r.sm3_hmac_ok = (r.sm3_hmac === EXP.sm3_hmac);
    
    // SM2
    r.sm2_enc = SM2Util.encrypt(MSG, D.sm2_enc_pub, false);
    r.sm2_sig = SM2Util.sign(MSG, D.sm2_sig_priv, false);
    // SM4
    const sm4key = Buffer.from(D.sm4_key, 'hex');
    r.sm4_enc = SM4Util.encryptGcmString(MSG, sm4key);
    
    // Verify reference
    const refFile = process.argv[2];
    if (refFile) {
        const fs = require('fs');
        const ref = JSON.parse(fs.readFileSync(refFile, 'utf8'));
        try {
            r.sm2_dec_ok = (SM2Util.decrypt(ref.sm2_enc, D.sm2_enc_priv) === MSG);
        } catch(e) { r.sm2_dec_ok = false; }
        try {
            r.sm2_ver_ok = SM2Util.verify(MSG, D.sm2_sig_pub, ref.sm2_sig);
        } catch(e) { r.sm2_ver_ok = false; }
        try {
            const es = ref.sm2_enc_sign || {};
            const ok = SM2Util.verify(es.cipher, D.sm2_sig_pub, es.sig);
            const dec = ok ? SM2Util.decrypt(es.cipher, D.sm2_enc_priv) : null;
            r.sm2_esvd_ok = (ok && dec === MSG);
        } catch(e) { r.sm2_esvd_ok = false; }
        try {
            r.sm4_dec_ok = (SM4Util.decryptGcmToString(ref.sm4_enc, sm4key) === MSG);
        } catch(e) { r.sm4_dec_ok = false; }
    }
    console.log(JSON.stringify(r));
}
main().catch(e => { console.log(JSON.stringify({error: e.message})); });
