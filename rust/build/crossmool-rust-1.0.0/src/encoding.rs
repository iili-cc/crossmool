use base64::{engine::general_purpose, Engine as _};

/// Encode bytes to hex string
pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode hex string to bytes (case-insensitive)
pub fn from_hex(hexstr: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hexstr)
}

/// Encode bytes to Base64 string
pub fn to_base64(bytes: &[u8]) -> String {
    general_purpose::STANDARD.encode(bytes)
}

/// Decode Base64 string to bytes
pub fn from_base64(b64: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::STANDARD.decode(b64)
}

/// Basic helper to check if a string is hex (simple heuristic)
pub fn is_hex(s: &str) -> bool {
    // allow upper or lower hex, require even length
    if !s.len().is_multiple_of(2) {
        return false;
    }
    s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Basic helper to check if a string is base64 (heuristic)
pub fn is_base64(s: &str) -> bool {
    general_purpose::STANDARD.decode(s).is_ok()
}
