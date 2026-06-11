
const D = {"msg": "Hello, \u8fd9\u662f\u8de8\u8bed\u8a00\u56fd\u5bc6\u4e92\u901a\u6027\u6d4b\u8bd5\u6570\u636e", "enc_priv": "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03", "enc_pub": "04c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356", "sig_priv": "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3", "sig_pub": "04192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", "sm4_key": "0123456789abcdeffedcba9876543210", "hmac_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"};
const MSG = D.msg;
const PATH = "D:/workspaces/git/corssmool/crossmool\javascript\crossmool";

async function main() {
    let SM2Util, SM3Util, SM4Util, bytesToHex;
    try {
        // Try ESM
        const m = await import("file://" + PATH + "/dist/index.mjs");
        SM2Util = m.SM2Util; SM3Util = m.SM3Util; SM4Util = m.SM4Util;
    } catch(e) {
        // Try CJs
        const m = require(PATH + "/dist/index.js");
        SM2Util = m.SM2Util; SM3Util = m.SM3Util; SM4Util = m.SM4Util;
    }
    
    const r = {};
    // SM2 Enc/Dec
    try {
        r.sm2_enc = SM2Util.encrypt(MSG, D.enc_pub, false);
        r.sm2_enc_dec = (SM2Util.decrypt(r.sm2_enc, D.enc_priv) === MSG) ? "PASS" : "FAIL";
    } catch(e) { r.sm2_enc_dec = "FAIL:"+e.message; }
    // SM2 Sig/Ver
    try {
        r.sm2_sig = SM2Util.sign(MSG, D.sig_priv, false);
        r.sm2_sig_ver = SM2Util.verify(MSG, D.sig_pub, r.sm2_sig) ? "PASS" : "FAIL";
    } catch(e) { r.sm2_sig_ver = "FAIL:"+e.message; }
    // SM3
    r.sm3_hash = SM3Util.digest(MSG);
    // SM3-HMAC
    r.sm3_hmac_hash = SM3Util.hmac(D.hmac_key, MSG);
    // SM4
    try {
        const sk = Buffer.from(D.sm4_key, 'hex');
        r.sm4_enc = SM4Util.encryptGcmString(MSG, sk);
        r.sm4_enc_dec = (SM4Util.decryptGcmToString(r.sm4_enc, sk) === MSG) ? "PASS" : "FAIL";
    } catch(e) { r.sm4_enc_dec = "FAIL:"+e.message; }
    r.cross = {sm2_enc: r.sm2_enc, sm2_sig: r.sm2_sig, sm4_enc: r.sm4_enc, sm3_hash: r.sm3_hash, sm3_hmac_hash: r.sm3_hmac_hash};
    console.log(JSON.stringify(r));
}
main().catch(e => console.log(JSON.stringify({error: e.message})));
