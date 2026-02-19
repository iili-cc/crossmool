use base64::engine::general_purpose;
use base64::Engine;
use hmac::{Hmac, Mac};
use sm3::{Digest, Sm3};

/// SM3 helpers
/// Uses the `sm3` crate (RustCrypto-style). The API below returns bytes and
/// convenience hex/base64 encodings.
pub fn digest_bytes(data: &[u8]) -> Vec<u8> {
    Sm3::digest(data).to_vec()
}

pub fn digest_hex(data: &[u8]) -> String {
    hex::encode(digest_bytes(data))
}

pub fn digest_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(digest_bytes(data))
}

/// HMAC-SM3 using RustCrypto-style HMAC + SM3
pub fn hmac_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacSm3 = Hmac<Sm3>;
    let mut mac = HmacSm3::new_from_slice(key).expect("HMAC key length invalid");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    hex::encode(hmac_bytes(key, data))
}

pub fn hmac_base64(key: &[u8], data: &[u8]) -> String {
    general_purpose::STANDARD.encode(hmac_bytes(key, data))
}
