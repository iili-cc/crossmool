//! SM4 helpers
//!
//! This module uses the `sm4` crate (external) to provide PKCS7-padded ECB encryption/decryption
//! to match the Java `SM4Util` behavior. It exposes byte/hex/base64 helpers similar to Java.

use base64::engine::general_purpose;
use base64::Engine as _;
use generic_array::GenericArray;
use sm4::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};
use sm4::Sm4;

/// Encrypt bytes (ECB/PKCS7) -> raw ciphertext bytes
pub fn encrypt_ecb_bytes(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err("SM4 key must be 16 bytes".into());
    }
    // PKCS7 padding
    let block_size = 16usize;
    let pad_len = block_size - (plaintext.len() % block_size);
    let mut buf = plaintext.to_vec();
    buf.extend(std::iter::repeat_n(pad_len as u8, pad_len));

    let mut cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {:?}", e))?;
    let mut out = vec![0u8; buf.len()];
    for (chunk_in, chunk_out) in buf.chunks(16).zip(out.chunks_mut(16)) {
        let mut block = GenericArray::clone_from_slice(chunk_in);
        cipher.encrypt_block_mut(&mut block);
        chunk_out.copy_from_slice(&block);
    }
    Ok(out)
}

/// Decrypt bytes (ECB/PKCS7)
pub fn decrypt_ecb_bytes(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err("SM4 key must be 16 bytes".into());
    }
    if !ciphertext.len().is_multiple_of(16) {
        return Err("ciphertext length must be multiple of 16".into());
    }
    let mut cipher = Sm4::new_from_slice(key).map_err(|e| format!("invalid key: {:?}", e))?;
    let mut out = vec![0u8; ciphertext.len()];
    for (chunk_in, chunk_out) in ciphertext.chunks(16).zip(out.chunks_mut(16)) {
        let mut block = GenericArray::clone_from_slice(chunk_in);
        cipher.decrypt_block_mut(&mut block);
        chunk_out.copy_from_slice(&block);
    }
    // remove PKCS7 padding
    if let Some(&pad) = out.last() {
        let pad = pad as usize;
        if pad == 0 || pad > 16 || pad > out.len() {
            return Err("invalid padding".into());
        }
        out.truncate(out.len() - pad);
    }
    Ok(out)
}

/// Convenience: encrypt -> hex string
pub fn encrypt_ecb_hex(key: &[u8], plaintext: &[u8]) -> Result<String, String> {
    let c = encrypt_ecb_bytes(key, plaintext)?;
    Ok(hex::encode(c))
}

/// Convenience: decrypt from hex string
pub fn decrypt_ecb_hex(key: &[u8], hex_ciphertext: &str) -> Result<Vec<u8>, String> {
    let c = hex::decode(hex_ciphertext).map_err(|e| format!("hex decode error: {:?}", e))?;
    decrypt_ecb_bytes(key, &c)
}

/// Convenience: encrypt -> base64
pub fn encrypt_ecb_base64(key: &[u8], plaintext: &[u8]) -> Result<String, String> {
    let c = encrypt_ecb_bytes(key, plaintext)?;
    Ok(general_purpose::STANDARD.encode(c))
}

/// Convenience: decrypt from base64
pub fn decrypt_ecb_base64(key: &[u8], b64_ciphertext: &str) -> Result<Vec<u8>, String> {
    let c = general_purpose::STANDARD
        .decode(b64_ciphertext)
        .map_err(|e| format!("base64 decode error: {:?}", e))?;
    decrypt_ecb_bytes(key, &c)
}
