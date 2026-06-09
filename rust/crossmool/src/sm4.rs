//! SM4 encryption utilities (GCM + legacy ECB)
//!
//! GCM mode: IV=12 bytes, Tag=16 bytes, no AAD
//! Output format: Hex(IV + ciphertext + Tag) by default, or Base64(IV + ciphertext + Tag)

use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use sm4::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};
use sm4::Sm4;
use subtle::ConstantTimeEq;

use crate::encoding;

const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const SM4_KEY_LEN: usize = 16;
const SM4_BLOCK_LEN: usize = 16;

// ========================
// Key generation
// ========================

/// Generate a random 16-byte SM4 key
pub fn generate_key() -> Vec<u8> {
    let mut key = vec![0u8; SM4_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

// ========================
// GCM mode
// ========================

/// Encrypt using SM4-GCM with a random IV.
/// Returns Hex(IV + ciphertext + Tag) by default, or Base64 if to_base64=true
pub fn encrypt_gcm(key: &[u8], plain: &[u8], to_base64: bool) -> Result<String, String> {
    let mut iv = vec![0u8; GCM_IV_LEN];
    rand::thread_rng().fill_bytes(&mut iv);
    encrypt_gcm_with_iv(key, plain, &iv, to_base64)
}

/// Encrypt using SM4-GCM with a specific IV.
/// Returns Hex(IV + ciphertext + Tag) by default, or Base64 if to_base64=true
pub fn encrypt_gcm_with_iv(key: &[u8], plain: &[u8], iv: &[u8], to_base64: bool) -> Result<String, String> {
    validate_key(key)?;
    if iv.len() != GCM_IV_LEN {
        return Err(format!("GCM IV must be {} bytes", GCM_IV_LEN));
    }

    let cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {}", e))?;
    let (ciphertext, tag) = gcm_encrypt(&cipher, iv, b"", plain);

    let mut result = Vec::with_capacity(iv.len() + ciphertext.len() + tag.len());
    result.extend_from_slice(iv);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);

    if to_base64 {
        Ok(general_purpose::STANDARD.encode(&result))
    } else {
        Ok(hex::encode(&result))
    }
}

/// Encrypt using SM4-GCM with a random IV, always output Hex
pub fn encrypt_gcm_hex(key: &[u8], plain: &[u8]) -> Result<String, String> {
    encrypt_gcm(key, plain, false)
}

/// Encrypt using SM4-GCM with a specific IV, always output Hex
pub fn encrypt_gcm_hex_with_iv(key: &[u8], plain: &[u8], iv: &[u8]) -> Result<String, String> {
    encrypt_gcm_with_iv(key, plain, iv, false)
}

/// Encrypt using SM4-GCM with a random IV, always output Base64 (compatibility alias)
pub fn encrypt_gcm_base64(key: &[u8], plain: &[u8]) -> Result<String, String> {
    encrypt_gcm(key, plain, true)
}

/// Encrypt using SM4-GCM with a specific IV, always output Base64 (compatibility alias)
pub fn encrypt_gcm_base64_with_iv(key: &[u8], plain: &[u8], iv: &[u8]) -> Result<String, String> {
    encrypt_gcm_with_iv(key, plain, iv, true)
}

/// Decrypt SM4-GCM ciphertext (auto-detect Hex or Base64 input)
pub fn decrypt_gcm(key: &[u8], encoded: &str) -> Result<Vec<u8>, String> {
    validate_key(key)?;

    let data = decode_hex_or_base64(encoded)?;

    if data.len() < GCM_IV_LEN + GCM_TAG_LEN {
        return Err("invalid GCM data: too short".into());
    }

    let iv = &data[..GCM_IV_LEN];
    let ciphertext = &data[GCM_IV_LEN..data.len() - GCM_TAG_LEN];
    let tag = &data[data.len() - GCM_TAG_LEN..];

    let cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {}", e))?;
    gcm_decrypt(&cipher, iv, b"", ciphertext, tag)
}

/// Decrypt SM4-GCM Hex ciphertext
pub fn decrypt_gcm_from_hex(key: &[u8], hex_str: &str) -> Result<Vec<u8>, String> {
    validate_key(key)?;

    let data = hex::decode(hex_str).map_err(|e| format!("hex decode error: {}", e))?;

    if data.len() < GCM_IV_LEN + GCM_TAG_LEN {
        return Err("invalid GCM data: too short".into());
    }

    let iv = &data[..GCM_IV_LEN];
    let ciphertext = &data[GCM_IV_LEN..data.len() - GCM_TAG_LEN];
    let tag = &data[data.len() - GCM_TAG_LEN..];

    let cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {}", e))?;
    gcm_decrypt(&cipher, iv, b"", ciphertext, tag)
}

/// Decrypt SM4-GCM Base64 ciphertext (compatibility alias)
pub fn decrypt_gcm_base64(key: &[u8], encoded: &str) -> Result<Vec<u8>, String> {
    validate_key(key)?;

    let data = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("base64 decode error: {}", e))?;

    if data.len() < GCM_IV_LEN + GCM_TAG_LEN {
        return Err("invalid GCM data: too short".into());
    }

    let iv = &data[..GCM_IV_LEN];
    let ciphertext = &data[GCM_IV_LEN..data.len() - GCM_TAG_LEN];
    let tag = &data[data.len() - GCM_TAG_LEN..];

    let cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {}", e))?;
    gcm_decrypt(&cipher, iv, b"", ciphertext, tag)
}

/// Decrypt SM4-GCM ciphertext and return UTF-8 string (auto-detect Hex/Base64 input)
pub fn decrypt_gcm_to_string(key: &[u8], encoded: &str) -> Result<String, String> {
    let plain = decrypt_gcm(key, encoded)?;
    String::from_utf8(plain).map_err(|e| format!("utf8 error: {}", e))
}

/// Decrypt SM4-GCM Base64 ciphertext and return UTF-8 string (compatibility alias)
pub fn decrypt_gcm_base64_to_string(key: &[u8], encoded: &str) -> Result<String, String> {
    let plain = decrypt_gcm_base64(key, encoded)?;
    String::from_utf8(plain).map_err(|e| format!("utf8 error: {}", e))
}

/// Encrypt UTF-8 string using SM4-GCM with to_base64 flag (default Hex)
pub fn encrypt_gcm_string(key: &[u8], plain: &str, to_base64: bool) -> Result<String, String> {
    encrypt_gcm(key, plain.as_bytes(), to_base64)
}

// ========================
// Encoding helpers
// ========================

/// Decode a string that is either Hex or Base64
fn decode_hex_or_base64(s: &str) -> Result<Vec<u8>, String> {
    if encoding::is_hex(s) {
        hex::decode(s).map_err(|e| format!("hex decode error: {}", e))
    } else {
        general_purpose::STANDARD
            .decode(s)
            .map_err(|e| format!("base64 decode error: {}", e))
    }
}

// ========================
// GCM internals
// ========================

fn sm4_encrypt_block(cipher: &Sm4, block: &[u8]) -> [u8; 16] {
    let mut b = generic_array::GenericArray::clone_from_slice(block);
    cipher.encrypt_block_mut(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

fn sm4_decrypt_block(cipher: &Sm4, block: &[u8]) -> [u8; 16] {
    let mut b = generic_array::GenericArray::clone_from_slice(block);
    cipher.decrypt_block_mut(&mut b);
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    out
}

/// GF(2^128) multiplication with reduction polynomial x^128 + x^7 + x^2 + x + 1
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for i in 0..16 {
        for j in 0..8 {
            if (x[i] >> (7 - j)) & 1 != 0 {
                for k in 0..16 {
                    z[k] ^= v[k];
                }
            }
            // Right shift V by 1 bit
            let lsb = v[15] & 1;
            for k in (1..16).rev() {
                v[k] = (v[k] >> 1) | (v[k - 1] << 7);
            }
            v[0] >>= 1;
            // Conditional XOR with R = 0xe1 || 0^120
            if lsb != 0 {
                v[0] ^= 0xe1;
            }
        }
    }
    z
}

/// GHASH function
fn ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // Process AAD (pad to 16-byte boundary)
    for chunk in aad.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }

    // Process ciphertext (pad to 16-byte boundary)
    for chunk in ciphertext.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            y[i] ^= block[i];
        }
        y = gf128_mul(&y, h);
    }

    // Length block: len(A) || len(C) in bits, each 64-bit big-endian
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());

    for i in 0..16 {
        y[i] ^= len_block[i];
    }
    y = gf128_mul(&y, h);

    y
}

/// Increment the 32-bit counter (big-endian) in the last 4 bytes
fn inc32(counter: &[u8; 16]) -> [u8; 16] {
    let mut c = *counter;
    let val = u32::from_be_bytes([c[12], c[13], c[14], c[15]]);
    let inc = val.wrapping_add(1);
    c[12..16].copy_from_slice(&inc.to_be_bytes());
    c
}

/// GCM encrypt: returns (ciphertext, tag)
fn gcm_encrypt(cipher: &Sm4, iv: &[u8], aad: &[u8], plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // H = SM4_K(0^128)
    let h = sm4_encrypt_block(cipher, &[0u8; 16]);

    // J0 = IV || 0x00000001 (for 96-bit IV)
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[12..16].copy_from_slice(&1u32.to_be_bytes());

    // CTR encryption starting from inc32(J0)
    let mut counter = inc32(&j0);
    let mut ciphertext = Vec::with_capacity(plain.len());

    for chunk in plain.chunks(16) {
        let keystream = sm4_encrypt_block(cipher, &counter);
        for (i, &b) in chunk.iter().enumerate() {
            ciphertext.push(b ^ keystream[i]);
        }
        counter = inc32(&counter);
    }

    // Tag = GHASH(H, AAD, CT) XOR SM4_K(J0)
    let ghash_out = ghash(&h, aad, &ciphertext);
    let j0_enc = sm4_encrypt_block(cipher, &j0);

    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash_out[i] ^ j0_enc[i];
    }

    (ciphertext, tag.to_vec())
}

/// GCM decrypt: verifies tag and returns plaintext
fn gcm_decrypt(cipher: &Sm4, iv: &[u8], aad: &[u8], ciphertext: &[u8], tag: &[u8]) -> Result<Vec<u8>, String> {
    // H = SM4_K(0^128)
    let h = sm4_encrypt_block(cipher, &[0u8; 16]);

    // J0 = IV || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(iv);
    j0[12..16].copy_from_slice(&1u32.to_be_bytes());

    // Verify tag: GHASH(H, AAD, CT) XOR SM4_K(J0)
    let ghash_out = ghash(&h, aad, ciphertext);
    let j0_enc = sm4_encrypt_block(cipher, &j0);

    let mut computed_tag = [0u8; 16];
    for i in 0..16 {
        computed_tag[i] = ghash_out[i] ^ j0_enc[i];
    }

    if computed_tag.ct_eq(tag).into() == false {
        return Err("GCM authentication failed".into());
    }

    // CTR decryption starting from inc32(J0)
    let mut counter = inc32(&j0);
    let mut plain = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks(16) {
        let keystream = sm4_encrypt_block(cipher, &counter);
        for (i, &b) in chunk.iter().enumerate() {
            plain.push(b ^ keystream[i]);
        }
        counter = inc32(&counter);
    }

    Ok(plain)
}

// ========================
// Legacy ECB mode
// ========================

/// Encrypt using SM4-ECB with PKCS#7 padding, return hex string
pub fn encrypt_ecb_hex(key: &[u8], plain: &[u8]) -> Result<String, String> {
    let cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {}", e))?;
    let padded = pkcs7_pad(plain);
    let mut result = vec![0u8; padded.len()];

    for (i, chunk) in padded.chunks(16).enumerate() {
        let mut block = generic_array::GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block_mut(&mut block);
        result[i * 16..(i + 1) * 16].copy_from_slice(&block);
    }

    Ok(hex::encode(&result))
}

/// Decrypt SM4-ECB hex ciphertext, return raw bytes
pub fn decrypt_ecb_hex(key: &[u8], cipher_hex: &str) -> Result<Vec<u8>, String> {
    let data = hex::decode(cipher_hex).map_err(|e| format!("hex decode error: {}", e))?;
    decrypt_ecb_bytes(key, &data)
}

/// Encrypt using SM4-ECB with PKCS#7 padding, return base64 string
pub fn encrypt_ecb_base64(key: &[u8], plain: &[u8]) -> Result<String, String> {
    let cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {}", e))?;
    let padded = pkcs7_pad(plain);
    let mut result = vec![0u8; padded.len()];

    for (i, chunk) in padded.chunks(16).enumerate() {
        let mut block = generic_array::GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block_mut(&mut block);
        result[i * 16..(i + 1) * 16].copy_from_slice(&block);
    }

    Ok(general_purpose::STANDARD.encode(&result))
}

/// Decrypt SM4-ECB base64 ciphertext, return raw bytes
pub fn decrypt_ecb_base64(key: &[u8], cipher_b64: &str) -> Result<Vec<u8>, String> {
    let data = general_purpose::STANDARD
        .decode(cipher_b64)
        .map_err(|e| format!("base64 decode error: {}", e))?;
    decrypt_ecb_bytes(key, &data)
}

/// Decrypt SM4-ECB raw bytes with PKCS#7 unpadding
pub fn decrypt_ecb_bytes(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() % 16 != 0 {
        return Err("invalid ECB data: not a multiple of block size".into());
    }

    let cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {}", e))?;
    let mut plain = vec![0u8; data.len()];

    for (i, chunk) in data.chunks(16).enumerate() {
        let mut block = generic_array::GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block_mut(&mut block);
        plain[i * 16..(i + 1) * 16].copy_from_slice(&block);
    }

    pkcs7_unpad(&plain)
}

// ========================
// helpers
// ========================

fn validate_key(key: &[u8]) -> Result<(), String> {
    if key.len() != SM4_KEY_LEN {
        return Err(format!("SM4 key must be {} bytes (128 bits)", SM4_KEY_LEN));
    }
    Ok(())
}

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let padding = 16 - data.len() % 16;
    let mut padded = Vec::with_capacity(data.len() + padding);
    padded.extend_from_slice(data);
    for _ in 0..padding {
        padded.push(padding as u8);
    }
    padded
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() {
        return Err("invalid padding: empty data".into());
    }
    let padding = data[data.len() - 1] as usize;
    if padding == 0 || padding > 16 || padding > data.len() {
        return Err("invalid PKCS#7 padding".into());
    }
    for i in 0..padding {
        if data[data.len() - 1 - i] as usize != padding {
            return Err("invalid PKCS#7 padding".into());
        }
    }
    Ok(data[..data.len() - padding].to_vec())
}

// ========================
// Tests
// ========================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcm_roundtrip_hex() {
        let key = generate_key();
        let plain = b"Hello, GCM!";
        let encrypted = encrypt_gcm(&key, plain, false).unwrap();
        let decrypted = decrypt_gcm(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_gcm_roundtrip_base64() {
        let key = generate_key();
        let plain = b"Hello, GCM!";
        let encrypted = encrypt_gcm(&key, plain, true).unwrap();
        let decrypted = decrypt_gcm(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_gcm_roundtrip_string() {
        let key = generate_key();
        let plain = "Hello, 這是国密SM4測試數據";
        let encrypted = encrypt_gcm_string(&key, plain, false).unwrap();
        let decrypted = decrypt_gcm_to_string(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_gcm_deterministic_with_iv() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let iv: Vec<u8> = (0u8..12).collect();
        let plain = b"Hello, 這是国密SM4測試數據";

        let enc1 = encrypt_gcm_with_iv(&key, plain, &iv, false).unwrap();
        let enc2 = encrypt_gcm_with_iv(&key, plain, &iv, false).unwrap();
        assert_eq!(enc1, enc2);

        let dec = decrypt_gcm_from_hex(&key, &enc1).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_gcm_tamper_detection() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plain = b"Hello, 這是国密SM4測試數據";
        let encrypted = encrypt_gcm_base64(&key, plain).unwrap();

        let tampered = &encrypted[..encrypted.len() - 2].to_string();
        let tampered = format!("{}XX", tampered);
        assert!(decrypt_gcm_base64(&key, &tampered).is_err());
    }

    #[test]
    fn test_gcm_java_interop() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let iv: Vec<u8> = (0u8..12).collect();
        let plain = "Hello, 這是国密SM4測試數據";

        // Encrypt with specific IV - should match Java output (Base64)
        let encrypted = encrypt_gcm_base64_with_iv(&key, plain.as_bytes(), &iv).unwrap();
        let java_cipher = "AAECAwQFBgcICQoLHUR0/d6difbkGWUzdLn96G1Wr/4NZVgH6lwAiXZ4q53any/1ebT8w7FURBOKOUB3W+c=";
        assert_eq!(encrypted, java_cipher, "Rust ciphertext does not match Java");

        // Decrypt Java ciphertext
        let decrypted = decrypt_gcm_base64_to_string(&key, java_cipher).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_gcm_auto_detect_decrypt() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let iv: Vec<u8> = (0u8..12).collect();
        let plain = b"Hello, 這是国密SM4測試數據";

        // Encrypt as Hex
        let hex_enc = encrypt_gcm_hex_with_iv(&key, plain, &iv).unwrap();
        // Encrypt as Base64
        let b64_enc = encrypt_gcm_base64_with_iv(&key, plain, &iv).unwrap();

        // Both should decrypt correctly with auto-detect
        let dec_from_hex = decrypt_gcm(&key, &hex_enc).unwrap();
        let dec_from_b64 = decrypt_gcm(&key, &b64_enc).unwrap();
        assert_eq!(dec_from_hex, plain);
        assert_eq!(dec_from_b64, plain);
    }

    #[test]
    fn test_gcm_hex_convenience() {
        let key = generate_key();
        let plain = b"Hello, GCM Hex!";
        let encrypted = encrypt_gcm_hex(&key, plain).unwrap();
        // Verify it's hex
        assert!(encoding::is_hex(&encrypted));
        let decrypted = decrypt_gcm_from_hex(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn test_ecb_roundtrip() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plain = b"Hello, 這是国密SM4測試數據";
        let encrypted = encrypt_ecb_base64(&key, plain).unwrap();
        let decrypted = decrypt_ecb_base64(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plain);
    }
}