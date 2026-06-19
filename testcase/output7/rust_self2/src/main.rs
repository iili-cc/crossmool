use crossmool::{sm2, sm3, sm4};
use hex;
use serde_json::{json, Value};

const MSG: &str = "Hello, 这是跨语言国密互通性测试数据";
const SM4_KEY: &str = "0123456789abcdeffedcba9876543210";
const HMAC_KEY: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const EXP_SM3: &str = "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b";
const EXP_SM3_HMAC: &str = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";

fn main() {
    let mut r = json!({"lang": "rust"});
    let enc_pub = "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    let enc_priv = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03a14403420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356";
    let sig_pub = "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    let sig_priv = "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3a14403420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226";
    let msg_bytes = MSG.as_bytes();

    match sm2::encrypt_to_hex(msg_bytes, enc_pub) {
        Ok(c) => {
            r["sm2_enc"] = Value::String(c.clone());
            match sm2::decrypt_from_hex(&c, enc_priv) {
                Ok(d) => {
                    let d_str = String::from_utf8_lossy(&d);
                    r["sm2_enc_dec"] = Value::String(if d_str == MSG { "PASS".to_string() } else { "FAIL".to_string() });
                }
                Err(e) => { r["sm2_enc_dec"] = Value::String(format!("FAIL: {}", e)); }
            }
        }
        Err(e) => { r["sm2_enc_dec"] = Value::String(format!("FAIL: {}", e)); }
    }

    match sm2::sign_to_hex(msg_bytes, sig_priv) {
        Ok(s) => {
            r["sm2_sig"] = Value::String(s.clone());
            match sm2::verify_from_hex(msg_bytes, sig_pub, &s) {
                Ok(ok) => { r["sm2_sig_ver"] = Value::String(if ok { "PASS".to_string() } else { "FAIL".to_string() }); }
                Err(e) => { r["sm2_sig_ver"] = Value::String(format!("FAIL: {}", e)); }
            }
        }
        Err(e) => { r["sm2_sig_ver"] = Value::String(format!("FAIL: {}", e)); }
    }

    match (sm2::encrypt_to_hex(msg_bytes, enc_pub), sm2::sign_to_hex(msg_bytes, sig_priv)) {
        (Ok(c2), Ok(s2)) => {
            match sm2::decrypt_from_hex(&c2, enc_priv) {
                Ok(d2) => {
                    let d2_str = String::from_utf8_lossy(&d2);
                    let ok2 = sm2::verify_from_hex(&d2, sig_pub, &s2).unwrap_or(false);
                    r["sm2_enc_sig_ver_dec"] = Value::String(if d2_str == MSG && ok2 { "PASS".to_string() } else { "FAIL".to_string() });
                }
                Err(e) => { r["sm2_enc_sig_ver_dec"] = Value::String(format!("FAIL: {}", e)); }
            }
        }
        _ => { r["sm2_enc_sig_ver_dec"] = Value::String("FAIL".to_string()); }
    }

    let h = sm3::digest_to_hex(msg_bytes);
    r["sm3_hash"] = Value::String(h.clone());
    r["sm3"] = Value::String(if h == EXP_SM3 { "PASS".to_string() } else { "FAIL".to_string() });

    let hmac_key = hex::decode(HMAC_KEY).unwrap();
    let hm = sm3::hmac_to_hex(&hmac_key, msg_bytes);
    r["sm3_hmac_hash"] = Value::String(hm.clone());
    r["sm3_hmac"] = Value::String(if hm == EXP_SM3_HMAC { "PASS".to_string() } else { "FAIL".to_string() });

    let sm4_key = hex::decode(SM4_KEY).unwrap();
    match sm4::encrypt_gcm(&sm4_key, msg_bytes, false) {
        Ok(sc) => {
            r["sm4_enc"] = Value::String(sc.clone());
            match sm4::decrypt_gcm_to_string(&sm4_key, &sc) {
                Ok(sd) => { r["sm4_enc_dec"] = Value::String(if sd == MSG { "PASS".to_string() } else { "FAIL".to_string() }); }
                Err(e) => { r["sm4_enc_dec"] = Value::String(format!("FAIL: {}", e)); }
            }
        }
        Err(e) => { r["sm4_enc_dec"] = Value::String(format!("FAIL: {}", e)); }
    }

    println!("{}", serde_json::to_string(&r).unwrap());
}
