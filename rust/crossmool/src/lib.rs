//! crossmool - Rust utilities for SM2/SM3/SM4 compatible with crossmool Java implementation
//!
//! This crate exposes simple helpers for SM2 (keygen, sign, verify, encrypt, decrypt),
//! SM3 (digest, hmac) and SM4 (encrypt/decrypt). It provides three serialization helpers:
//! - raw bytes
//! - hex string
//! - base64 string
//!
//! Implementation notes:
//! - The Java implementation uses BouncyCastle with SM2 mode C1C3C2 and SM2Signer with user id `1234567812345678`.
//! - This crate aims to be compatible with that format. Implementations use `ckb-crypto` where available,
//!   and fallback to commonly available crates (`sm2`, `sm3`, `sm4`) if needed. You may need to pin exact
//!   dependency versions in `Cargo.toml` for your environment.

pub mod encoding;
pub mod sm2;
pub mod sm3;
pub mod sm4;
