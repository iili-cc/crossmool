use base64::engine::general_purpose;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sm3::{Digest, Sm3};

use crate::encoding;

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

/// Compute SM3 digest with to_base64 flag (default Hex)
pub fn digest_to_str(data: &[u8], to_base64: bool) -> String {
    let hash = digest_bytes(data);
    if to_base64 {
        encoding::to_base64(&hash)
    } else {
        encoding::to_hex(&hash)
    }
}

/// Compute SM3 digest from UTF-8 string input, with to_base64 flag (default Hex)
pub fn digest_str(input: &str, to_base64: bool) -> String {
    let data = input.as_bytes();
    digest_to_str(data, to_base64)
}

/// Compute SM3 digest from UTF-8 string input, default Hex output
pub fn digest_str_default(input: &str) -> String {
    digest_str(input, false)
}

/// HMAC-SM3 using RustCrypto-style HMAC + SM3
/// Param order: data first, key second (consistent with Java/other languages)
pub fn hmac_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    type HmacSm3 = Hmac<Sm3>;
    let mut mac = HmacSm3::new_from_slice(key).expect("HMAC key length invalid");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn hmac_hex(data: &[u8], key: &[u8]) -> String {
    hex::encode(hmac_bytes(data, key))
}

pub fn hmac_base64(data: &[u8], key: &[u8]) -> String {
    general_purpose::STANDARD.encode(hmac_bytes(data, key))
}

/// HMAC-SM3 with to_base64 flag (default Hex)
pub fn hmac_to_str(data: &[u8], key: &[u8], to_base64: bool) -> String {
    let mac = hmac_bytes(data, key);
    if to_base64 {
        encoding::to_base64(&mac)
    } else {
        encoding::to_hex(&mac)
    }
}

/// Parse string input: auto-detect Hex/Base64, fallback to UTF-8 bytes
/// For key: must be Hex or Base64 (no UTF-8 fallback)
/// For data: Hex, Base64, or UTF-8 fallback
fn parse_key_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Err("key cannot be empty".into());
    }
    if encoding::is_hex(s) {
        encoding::from_hex(s).map_err(|e| format!("hex decode error: {}", e))
    } else if encoding::is_base64(s) {
        encoding::from_base64(s).map_err(|e| format!("base64 decode error: {}", e))
    } else {
        Err("key must be Hex string or Base64 string".into())
    }
}

fn parse_data_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Err("data cannot be empty".into());
    }
    if encoding::is_hex(s) {
        encoding::from_hex(s).map_err(|e| format!("hex decode error: {}", e))
    } else if encoding::is_base64(s) {
        encoding::from_base64(s).map_err(|e| format!("base64 decode error: {}", e))
    } else {
        Ok(s.as_bytes().to_vec())
    }
}

/// HMAC-SM3 from string data/key, auto-detect Hex/Base64 for key, auto-detect Hex/Base64/UTF-8 for data
pub fn hmac_from_str(data: &str, key: &str) -> Result<Vec<u8>, String> {
    let key_bytes = parse_key_bytes(key)?;
    let data_bytes = parse_data_bytes(data)?;
    Ok(hmac_bytes(&data_bytes, &key_bytes))
}

/// HMAC-SM3 from string data/key with to_base64 flag, auto-detect encoding
pub fn hmac_str(data: &str, key: &str, to_base64: bool) -> Result<String, String> {
    let mac = hmac_from_str(data, key)?;
    if to_base64 {
        Ok(encoding::to_base64(&mac))
    } else {
        Ok(encoding::to_hex(&mac))
    }
}

/// HMAC-SM3 from string data/key, default Hex output
pub fn hmac_str_default(data: &str, key: &str) -> Result<String, String> {
    hmac_str(data, key, false)
}

/// Generate random HMAC key (bytes)
pub fn generate_hmac_key(length: usize) -> Vec<u8> {
    if length < 32 {
        panic!("HMAC key length must be at least 32 bytes");
    }
    let mut key = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Generate random HMAC key with to_base64 flag (default Hex)
pub fn generate_hmac_key_to_str(length: usize, to_base64: bool) -> String {
    let key = generate_hmac_key(length);
    if to_base64 {
        encoding::to_base64(&key)
    } else {
        encoding::to_hex(&key)
    }
}

/// Generate random 32-byte HMAC key with to_base64 flag (default Hex)
pub fn generate_hmac_key_str(to_base64: bool) -> String {
    generate_hmac_key_to_str(32, to_base64)
}

/// Generate random 32-byte HMAC key, default Hex output
pub fn generate_hmac_key_str_default() -> String {
    generate_hmac_key_to_str(32, false)
}

/// Verify HMAC-SM3 by computing expected value and comparing.
pub fn hmac_verify(data: &str, key: &str, received_hmac: &str) -> Result<bool, String> {
    let expected = hmac_str_default(data, key)?;
    Ok(expected == received_hmac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_to_str() {
        let data = b"hello";
        let hex_result = digest_to_str(data, false);
        let b64_result = digest_to_str(data, true);
        assert_eq!(hex_result, digest_hex(data));
        assert_eq!(b64_result, digest_base64(data));
    }

    #[test]
    fn test_digest_str() {
        let input = "hello";
        let hex_result = digest_str(input, false);
        let b64_result = digest_str(input, true);
        assert_eq!(hex_result, digest_hex(input.as_bytes()));
        assert_eq!(b64_result, digest_base64(input.as_bytes()));
    }

    #[test]
    fn test_hmac_to_str() {
        let key = b"test-key-1234567890123456789012";
        let data = b"hello";
        let hex_result = hmac_to_str(data, key, false);
        let b64_result = hmac_to_str(data, key, true);
        assert_eq!(hex_result, hmac_hex(data, key));
        assert_eq!(b64_result, hmac_base64(data, key));
    }

    #[test]
    fn test_hmac_str_auto_detect() {
        let key_hex = hex::encode(b"test-key-1234567890123456789012");
        let data = "hello";
        let result = hmac_str(data, &key_hex, false).unwrap();
        let expected = hmac_hex(data.as_bytes(), b"test-key-1234567890123456789012");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_generate_hmac_key_to_str() {
        let hex_key = generate_hmac_key_to_str(32, false);
        let b64_key = generate_hmac_key_to_str(32, true);
        assert_eq!(hex_key.len(), 64); // 32 bytes = 64 hex chars
        assert!(encoding::is_hex(&hex_key));
        assert!(encoding::is_base64(&b64_key));
    }

    #[test]
    fn test_hmac_roundtrip_with_generated_key() {
        let key_hex = generate_hmac_key_to_str(32, false);
        let data = "test data for hmac";
        let mac_hex = hmac_str(data, &key_hex, false).unwrap();
        // Verify the mac can be reproduced
        let mac_hex2 = hmac_str(data, &key_hex, false).unwrap();
        assert_eq!(mac_hex, mac_hex2);
    }

    #[test]
    fn test_hmac_cross_language_vector() {
        // Fixed cross-language interoperability vector shared by all 8 languages
        let msg = "Hello, 这是跨语言国密互通性测试数据";
        let hmac_key_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let expected = "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6";
        let result = hmac_str(msg, hmac_key_hex, false).unwrap();
        assert_eq!(result, expected);
        assert!(hmac_verify(msg, hmac_key_hex, expected).unwrap());
    }
}