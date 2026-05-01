crossmool - Rust SM2/SM3/SM4 utilities
=====================================

This crate provides utilities to interoperate with the Java implementation in this repository (`java/crossmool`). It aims to use `ckb-crypto` for SM2/SM3 and a standalone `sm4` crate for SM4.

Status
------
- Encoding helpers (hex/base64) implemented.
- SM4 (ECB with PKCS7) implemented using the `sm4` crate.
- SM3 implemented using RustCrypto-style `sm3` crate.
- SM2 module exposes the API surface and placeholders; it must be adapted to the concrete SM2 crate API you want to use (e.g. `ckb-crypto` exact version). See implementation notes below.

Compatibility notes
-------------------
- Java `SM2Util` uses BouncyCastle `SM2Engine.Mode.C1C3C2` for encryption. Any Rust SM2 implementation must output/read ciphertext in C1C3C2 order to be interoperable.
- Java `SM2Util` signs using `SM2Signer` with user id `1234567812345678`. When implementing signatures in Rust, make sure to use the same user id and the same signature encoding (Bouncy Castle returns DER-encoded signature bytes from `generateSignature()`).
- SM3 digest and HMAC-SM3 must match BouncyCastle outputs; the Rust `sm3` crate (RustCrypto-style) is compatible.
- SM4 ECB/PKCS7 implemented and returns raw cipher bytes; helpers provided for hex/base64.

Next steps for full SM2 support
------------------------------
1. Choose the exact `ckb-crypto` version to use (or another SM2 crate). Update `Cargo.toml` to pin that version.
2. Replace the placeholder code in `src/sm2.rs` with the concrete API calls:
	- key generation that returns public key in X.509/SubjectPublicKeyInfo DER and private key in PKCS#8 DER (so Java and Rust can exchange keys as Base64/Hex strings)
	- sign/verify using the same SM2 user id
	- encrypt/decrypt using C1C3C2 ordering

If you want, I can now:
- implement SM2 using a specific `ckb-crypto` version (tell me which version), or
- attempt an implementation using the `sm2` crate currently listed in `Cargo.toml` (I will update `src/sm2.rs` accordingly and run `cargo build`).

Usage examples
--------------
See the module-level docs in `src/lib.rs` and the function names; once SM2 is implemented, you can:

- Generate keys: `sm2::generate_keypair()`
- Sign: `sm2::sign_bytes(msg, private_der)` -> bytes/hex/base64
- Verify: `sm2::verify_bytes(msg, sig, public_der)`
- Encrypt/Decrypt: `sm2::encrypt_bytes` / `sm2::decrypt_bytes`
- SM3 digest: `sm3::digest_bytes` / `digest_hex` / `digest_base64`
- SM4: `sm4::encrypt_ecb_hex` / `sm4::decrypt_ecb_hex` (key = 16 bytes)
