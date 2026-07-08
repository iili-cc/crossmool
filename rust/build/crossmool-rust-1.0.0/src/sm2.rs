//! SM2 helpers
//!
//! Provides SM2 key generation, sign and verify helpers compatible with the Java
//! `SM2Util` conventions used in this repository (DER key encodings, SM2Signer user-id
//! = "1234567812345678"). SM2 public-key encryption (PKE) producing C1C3C2
//! format is implemented in this module (C1 = uncompressed SEC1 point, C3 = SM3(Sx||M||Sy), C2 = M xor KDF).

use rand::rngs::OsRng;

use sm2::dsa::signature::{Signer, Verifier};
use sm2::dsa::{Signature, SigningKey, VerifyingKey};
use sm2::elliptic_curve::sec1::FromEncodedPoint;
use sm2::elliptic_curve::sec1::ToEncodedPoint;
use sm2::elliptic_curve::AffinePoint;
use sm2::elliptic_curve::ProjectivePoint;
use sm2::pkcs8::LineEnding;
use sm2::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use sm2::Sm2;
use sm2::{PublicKey, SecretKey};
use sm3::{Digest, Sm3};
use base64::{engine::general_purpose, Engine as _};
use hex;

/// A simple container for serialized key pair (public/private) in DER/ASN.1 encoding.
#[derive(Debug, Clone)]
pub struct SerialKeyPair {
    /// Public key PEM (SPKI PEM / SubjectPublicKeyInfo)
    pub public_key_pem: String,
    /// Private key PEM (PKCS#8 PEM)
    pub private_key_pem: String,
}

/// Encrypt and return ciphertext as lowercase hex string (C1C3C2)
pub fn encrypt_with_public_pem_hex(public_pem: &str, plaintext: &[u8]) -> Result<String, String> {
    let ct = encrypt_with_public_pem(public_pem, plaintext)?;
    Ok(hex::encode(ct))
}

/// Encrypt and return ciphertext as base64 (C1C3C2)
pub fn encrypt_with_public_pem_base64(public_pem: &str, plaintext: &[u8]) -> Result<String, String> {
    let ct = encrypt_with_public_pem(public_pem, plaintext)?;
    Ok(general_purpose::STANDARD.encode(ct))
}

/// Decrypt ciphertext provided as lowercase hex (C1C3C2)
pub fn decrypt_with_private_pem_hex(private_pem: &str, ciphertext_hex: &str) -> Result<Vec<u8>, String> {
    let ct = hex::decode(ciphertext_hex).map_err(|e| format!("hex decode error: {:?}", e))?;
    decrypt_with_private_pem(private_pem, &ct)
}

/// Decrypt ciphertext provided as base64 (C1C3C2)
pub fn decrypt_with_private_pem_base64(private_pem: &str, ciphertext_b64: &str) -> Result<Vec<u8>, String> {
    let ct = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| format!("base64 decode error: {:?}", e))?;
    decrypt_with_private_pem(private_pem, &ct)
}

/// Generate an SM2 key pair and return PEM-encoded public/private keys.
pub fn generate_keypair() -> Result<SerialKeyPair, String> {
    let mut rng = OsRng;
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from_secret_scalar(&sk.to_nonzero_scalar());

    // Return PEM-encoded keys (more portable; PEM is base64-wrapped DER)
    let private_pem = sk
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| format!("private to pkcs8 pem error: {:?}", e))?;
    let public_pem = pk
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| format!("public to spki pem error: {:?}", e))?;

    Ok(SerialKeyPair {
        public_key_pem: public_pem.to_string(),
        private_key_pem: private_pem.to_string(),
    })
}

/// Generate an SM2 key pair and return hex-encoded raw keys.
/// Returns (public_key_hex, private_key_hex).
/// Public key: 130 chars (04+X+Y), Private key: 64 chars.
pub fn generate_keypair_hex() -> Result<(String, String), String> {
    let mut rng = OsRng;
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from_secret_scalar(&sk.to_nonzero_scalar());

    let pub_encoded = pk.to_encoded_point(false);
    let pub_hex = crate::encoding::to_hex(pub_encoded.as_bytes());

    // Extract private key bytes from PKCS8 DER
    let pkcs8_der = sk.to_pkcs8_der().map_err(|e| format!("pkcs8 der error: {:?}", e))?;
    // PKCS8 DER for SM2: the private key is a 32-byte OCTET STRING
    // We need to parse: SEQUENCE { INTEGER v, SEQUENCE alg, OCTET STRING wrapping ECPrivateKey }
    let priv_hex = crate::encoding::to_hex(&extract_private_key_from_pkcs8_der(pkcs8_der.as_bytes())?);

    Ok((pub_hex, priv_hex))
}

/// Extract the raw 32-byte private key from a PKCS#8 DER encoding.
fn extract_private_key_from_pkcs8_der(der: &[u8]) -> Result<Vec<u8>, String> {
    // Skip SEQUENCE header: first byte 0x30, then length
    let mut pos = 2;
    if pos >= der.len() { return Err("der too short".into()); }
    if der[1] & 0x80 != 0 { pos += (der[1] & 0x7f) as usize; }
    // Skip version INTEGER (3 bytes: 02 01 00)
    pos += 3;
    // Skip AlgorithmIdentifier SEQUENCE
    if pos + 1 >= der.len() || der[pos] != 0x30 { return Err("expected alg seq".into()); }
    pos += 1;
    let alg_len = der[pos] as usize; pos += 1;
    pos += alg_len;
    // Read OCTET STRING
    if pos + 1 >= der.len() || der[pos] != 0x04 { return Err("expected octet string".into()); }
    pos += 1;
    let octet_len = der[pos] as usize; pos += 1;
    let ec_der = &der[pos..pos + octet_len];
    // ECPrivateKey: SEQUENCE { INTEGER v=1, OCTET STRING d }
    let mut ep = 2; // skip 0x30 len
    if ec_der[0] != 0x30 || ec_der[1] & 0x80 != 0 { ep = if ec_der[1] & 0x80 != 0 { 2 + (ec_der[1] & 0x7f) as usize } else { 2 }; }
    ep += 3; // skip version INTEGER (02 01 01)
    if ep + 1 >= ec_der.len() || ec_der[ep] != 0x04 { return Err("expected ec priv octet".into()); }
    ep += 1;
    let d_len = ec_der[ep] as usize; ep += 1;
    Ok(ec_der[ep..ep + d_len].to_vec())
}

/// Generate an SM2 key pair and return base64-encoded raw keys.
/// Returns (public_key_base64, private_key_base64).
pub fn generate_keypair_base64() -> Result<(String, String), String> {
    let mut rng = OsRng;
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from_secret_scalar(&sk.to_nonzero_scalar());

    let pub_encoded = pk.to_encoded_point(false);
    let pub_b64 = crate::encoding::to_base64(pub_encoded.as_bytes());

    let pkcs8_der = sk.to_pkcs8_der().map_err(|e| format!("pkcs8 der error: {:?}", e))?;
    let priv_b64 = crate::encoding::to_base64(&extract_private_key_from_pkcs8_der(pkcs8_der.as_bytes())?);

    Ok((pub_b64, priv_b64))
}

/// Sign message bytes using PKCS#8 private key DER, returning signature bytes.
pub fn sign_bytes(msg: &[u8], private_pkcs8_der: &[u8]) -> Result<Vec<u8>, String> {
    let sk = SecretKey::from_pkcs8_der(private_pkcs8_der)
        .map_err(|e| format!("parse sk pkcs8 error: {:?}", e))?;
    let signing_key = SigningKey::new("1234567812345678", &sk)
        .map_err(|e| format!("create signing key error: {:?}", e))?;
    let sig = signing_key
        .try_sign(msg)
        .map_err(|e| format!("sign error: {:?}", e))?;
    Ok(sig.to_bytes().to_vec())
}

/// Sign message bytes using PKCS#8 private key PEM, returning signature bytes.
pub fn sign_with_private_pem(msg: &[u8], private_pkcs8_pem: &str) -> Result<Vec<u8>, String> {
    let sk = SecretKey::from_pkcs8_pem(private_pkcs8_pem)
        .map_err(|e| format!("parse sk pem error: {:?}", e))?;
    let signing_key = SigningKey::new("1234567812345678", &sk)
        .map_err(|e| format!("create signing key error: {:?}", e))?;
    let sig = signing_key
        .try_sign(msg)
        .map_err(|e| format!("sign error: {:?}", e))?;
    Ok(sig.to_bytes().to_vec())
}

/// Verify signature bytes using public key PEM (SPKI PEM)
pub fn verify_with_public_pem(
    msg: &[u8],
    signature: &[u8],
    public_pem: &str,
) -> Result<bool, String> {
    let pk = PublicKey::from_public_key_pem(public_pem)
        .map_err(|e| format!("parse public pem error: {:?}", e))?;
    let verifying_key = VerifyingKey::new("1234567812345678", pk)
        .map_err(|e| format!("create verifying key error: {:?}", e))?;
    if signature.len() != 64 {
        return Err("signature must be 64 bytes".into());
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature[0..64]);
    let sig =
        Signature::from_bytes(&sig_arr).map_err(|e| format!("invalid signature bytes: {:?}", e))?;
    verifying_key
        .verify(msg, &sig)
        .map(|_| true)
        .map_err(|e| format!("verify error: {:?}", e))
}

/// Verify signature bytes using X.509 SubjectPublicKeyInfo DER public key
pub fn verify_bytes(msg: &[u8], signature: &[u8], public_x509_der: &[u8]) -> Result<bool, String> {
    let pk = PublicKey::from_public_key_der(public_x509_der)
        .map_err(|e| format!("parse public der error: {:?}", e))?;
    let verifying_key = VerifyingKey::new("1234567812345678", pk)
        .map_err(|e| format!("create verifying key error: {:?}", e))?;
    if signature.len() != 64 {
        return Err("signature must be 64 bytes".into());
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature[0..64]);
    let sig =
        Signature::from_bytes(&sig_arr).map_err(|e| format!("invalid signature bytes: {:?}", e))?;
    verifying_key
        .verify(msg, &sig)
        .map(|_| true)
        .map_err(|e| format!("verify error: {:?}", e))
}

/// SM3-based KDF used by SM2. `z` is the input (Sx||Sy) and `klen` is output length in bytes.
fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut ct: u32 = 1;
    let mut out = Vec::with_capacity(klen);
    while out.len() < klen {
        let mut hasher = Sm3::new();
        hasher.update(z);
        hasher.update(ct.to_be_bytes());
        let h = hasher.finalize();
        out.extend_from_slice(&h);
        ct = ct.wrapping_add(1);
    }
    out.truncate(klen);
    out
}

/// Encrypt plaintext using recipient `PublicKey`. Returns C1||C3||C2 bytes (C1 uncompressed SEC1).
pub fn encrypt_with_publickey(pk: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut rng = OsRng;
    let ksk = SecretKey::random(&mut rng);
    // C1 = k * G
    let c1 = PublicKey::from_secret_scalar(&ksk.to_nonzero_scalar());
    let c1_bytes = c1.to_encoded_point(false).as_bytes().to_vec();

    // Compute shared point S = k * P
    let pk_point = pk.to_encoded_point(false);
    let pk_aff: AffinePoint<Sm2> =
        Into::<Option<AffinePoint<Sm2>>>::into(AffinePoint::<Sm2>::from_encoded_point(&pk_point))
            .ok_or("invalid public key point")?;
    let scalar = ksk.to_nonzero_scalar();
    let s_proj: ProjectivePoint<Sm2> = ProjectivePoint::<Sm2>::from(pk_aff) * *scalar;
    let s_aff = s_proj.to_affine();
    let s_enc = s_aff.to_encoded_point(false);
    let x = s_enc.x().ok_or("invalid shared point x")?;
    let y = s_enc.y().ok_or("invalid shared point y")?;

    let mut z = Vec::with_capacity(x.len() + y.len());
    z.extend_from_slice(x);
    z.extend_from_slice(y);

    let t = kdf(&z, plaintext.len());
    if t.iter().all(|&b| b == 0) {
        return Err("kdf returned all zero".into());
    }
    let mut c2 = vec![0u8; plaintext.len()];
    for i in 0..plaintext.len() {
        c2[i] = plaintext[i] ^ t[i];
    }

    // C3 = Hash(Sx || M || Sy)
    let mut h = Sm3::new();
    h.update(x);
    h.update(plaintext);
    h.update(y);
    let c3 = h.finalize().to_vec();

    let mut out = Vec::new();
    out.extend_from_slice(&c1_bytes);
    out.extend_from_slice(&c3);
    out.extend_from_slice(&c2);
    Ok(out)
}

/// Encrypt using recipient public key PEM (SPKI PEM)
pub fn encrypt_with_public_pem(public_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let pk = PublicKey::from_public_key_pem(public_pem)
        .map_err(|e| format!("parse public pem error: {:?}", e))?;
    encrypt_with_publickey(&pk, plaintext)
}

/// Decrypt ciphertext (C1||C3||C2) using PEM private key string (PKCS#8 PEM)
pub fn decrypt_with_private_pem(private_pem: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let sk = SecretKey::from_pkcs8_pem(private_pem)
        .map_err(|e| format!("parse private pem error: {:?}", e))?;

    if ciphertext.is_empty() {
        return Err("ciphertext empty".into());
    }
    if ciphertext[0] != 0x04 {
        return Err("only uncompressed C1 supported".into());
    }
    let coord_len = 32usize; // SM2 curve size
    let c1_len = 1 + 2 * coord_len;
    if ciphertext.len() < c1_len + 32 {
        return Err("ciphertext too short".into());
    }
    let c1_bytes = &ciphertext[0..c1_len];
    let c3 = &ciphertext[c1_len..c1_len + 32];
    let c2 = &ciphertext[c1_len + 32..];

    let c1_pk =
        PublicKey::from_sec1_bytes(c1_bytes).map_err(|e| format!("invalid c1 point: {:?}", e))?;
    let scalar = sk.to_nonzero_scalar();
    let c1_point = c1_pk.to_encoded_point(false);
    let c1_aff: AffinePoint<Sm2> =
        Into::<Option<AffinePoint<Sm2>>>::into(AffinePoint::<Sm2>::from_encoded_point(&c1_point))
            .ok_or("invalid c1 point")?;
    let s_proj: ProjectivePoint<Sm2> = ProjectivePoint::<Sm2>::from(c1_aff) * *scalar;
    let s_aff = s_proj.to_affine();
    let s_enc = s_aff.to_encoded_point(false);
    let x = s_enc.x().ok_or("invalid shared point x")?;
    let y = s_enc.y().ok_or("invalid shared point y")?;

    let mut z = Vec::with_capacity(x.len() + y.len());
    z.extend_from_slice(x);
    z.extend_from_slice(y);

    let t = kdf(&z, c2.len());
    if t.iter().all(|&b| b == 0) {
        return Err("kdf returned all zero".into());
    }
    let mut m = vec![0u8; c2.len()];
    for i in 0..c2.len() {
        m[i] = c2[i] ^ t[i];
    }

    // verify C3
    let mut h = Sm3::new();
    h.update(x);
    h.update(&m);
    h.update(y);
    let c3_calc = h.finalize();
    if c3_calc.as_slice() != c3 {
        return Err("c3 mismatch".into());
    }
    Ok(m)
}

/// Encrypt and sign in one pass. Uses different keys for encryption and signing.
pub fn encrypt_sign(plaintext: &[u8], enc_public_pem: &str, sign_private_pem: &str) -> Result<(String, String), String> {
    let ct_hex = encrypt_with_public_pem_hex(enc_public_pem, plaintext)?;
    let sig = sign_with_private_pem(plaintext, sign_private_pem)?;
    Ok((ct_hex, crate::encoding::to_hex(&sig)))
}

/// Verify signature and decrypt in one pass.
pub fn verify_decrypt(ciphertext_hex: &str, signature_hex: &str, sign_public_pem: &str, dec_private_pem: &str) -> Result<String, String> {
    let sig = crate::encoding::from_hex(signature_hex).map_err(|e| format!("hex decode: {:?}", e))?;
    let valid = verify_with_public_pem(ciphertext_hex.as_bytes(), &sig, sign_public_pem)?;
    if !valid {
        return Err("SM2 signature verification failed".into());
    }
    let pt = decrypt_with_private_pem_hex(dec_private_pem, ciphertext_hex)?;
    String::from_utf8(pt).map_err(|e| format!("utf8: {:?}", e))
}
