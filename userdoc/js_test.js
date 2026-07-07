
const { SM2Util } = require('./src/SM2Util');
const fs = require('fs');
const data = JSON.parse(fs.readFileSync('G:/workspaces/git/corssmool/crossmool/userdoc/test_vectors.json', 'utf-8'));
const r = {};
try {
    r.enc_hex = SM2Util.encrypt(data.plain1, data.enc_pub_hex) !== '';
    r.enc_b64 = SM2Util.encrypt(data.plain1, data.enc_pub_hex, true) !== '';
    r.dec_hex = SM2Util.decrypt(data.ct1_hex, data.enc_priv_hex) === data.plain1;
    r.dec_b64 = SM2Util.decrypt(data.ct1_b64, data.enc_priv_hex) === data.plain1;
    r.enc_sign_hex = SM2Util.encryptSign(data.plain2, data.enc_pub_hex, data.sig_priv_hex, false) !== null;
    r.enc_sign_b64 = SM2Util.encryptSign(data.plain2, data.enc_pub_hex, data.sig_priv_hex, true) !== null;
    r.vd_hex = SM2Util.verifyDecrypt(data.ct2_hex, data.sig2_hex, data.sig_pub_hex, data.enc_priv_hex) === data.plain2;
    r.vd_b64 = SM2Util.verifyDecrypt(data.ct2_b64, data.sig2_b64, data.sig_pub_hex, data.enc_priv_hex) === data.plain2;
    console.log(JSON.stringify(r));
} catch(e) { console.log(JSON.stringify({error: e.message})); }
