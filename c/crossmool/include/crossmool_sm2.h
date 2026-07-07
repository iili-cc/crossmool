#ifndef CROSSMOOL_SM2_H
#define CROSSMOOL_SM2_H

#include "crossmool_error.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// SM2 keypair structure (stores both HEX and Base64 formats)
typedef struct {
    char* private_key;          // Original private key (Base64 or HEX)
    char* public_key;           // Original public key (Base64 or HEX)
    char* private_key_hex;      // HEX format private key
    char* public_key_hex;       // HEX format public key
    char* private_key_base64;   // Base64 format private key
    char* public_key_base64;    // Base64 format public key
} crossmool_sm2_keypair_t;

// Ciphertext and signature pair structure
typedef struct {
    char* ciphertext;       // Ciphertext (same format as encryption)
    char* signature;        // Signature (same format as signing)
    char* ciphertext_hex;   // HEX format ciphertext
    char* signature_hex;    // HEX format signature
    char* ciphertext_base64;// Base64 format ciphertext
    char* signature_base64; // Base64 format signature
} crossmool_sm2_cipher_sig_pair_t;

/* ====================================================
 * Key Generation
 * ==================================================== */

/**
 * Generate SM2 keypair (returns pointer, auto-allocates memory)
 * Keys are stored in HEX format in private_key/public_key fields by default
 * @param keypair Output parameter, stores generated keypair pointer
 * @return 0 on success, negative error code on failure
 * @note Caller must call crossmool_sm2_keypair_free() to release memory
 */
CROSSMOOL_API int crossmool_sm2_generate_keypair(crossmool_sm2_keypair_t** keypair);

/**
 * Convert keypair to HEX format (fills private_key_hex / public_key_hex fields)
 * @param keypair Generated keypair
 * @return 0 on success, negative error code on failure
 */
CROSSMOOL_API int crossmool_sm2_keypair_to_hex(crossmool_sm2_keypair_t* keypair);

/**
 * Convert keypair to Base64 format (fills private_key_base64 / public_key_base64 fields)
 * @param keypair Generated keypair
 * @return 0 on success, negative error code on failure
 */
CROSSMOOL_API int crossmool_sm2_keypair_to_base64(crossmool_sm2_keypair_t* keypair);

/**
 * Generate SM2 keypair (Base64 encoded, direct struct)
 * @param keypair Output parameter, stores generated keypair
 * @return 0 on success, negative error code on failure
 */
CROSSMOOL_API int crossmool_sm2_generate_keypair_base64(crossmool_sm2_keypair_t* keypair);

/**
 * Generate SM2 keypair (HEX encoded, direct struct)
 * @param keypair Output parameter, stores generated keypair
 * @return 0 on success, negative error code on failure
 */
CROSSMOOL_API int crossmool_sm2_generate_keypair_hex(crossmool_sm2_keypair_t* keypair);

/**
 * Free keypair memory (pointer version)
 * @param keypair Keypair pointer to free
 */
CROSSMOOL_API void crossmool_sm2_keypair_free(crossmool_sm2_keypair_t* keypair);

/* ====================================================
 * Encryption / Decryption
 * ==================================================== */

/**
 * SM2 encryption (auto-detect charset, output HEX string)
 * @param content  Plaintext string (C string, null-terminated)
 * @param charset  Character set (can be NULL for UTF-8)
 * @param public_key Public key (supports HEX or Base64)
 * @param ciphertext_hex Output HEX format ciphertext
 * @return 0 on success, negative error code on failure
 * @note Caller must call free() to release ciphertext_hex
 */
CROSSMOOL_API int crossmool_sm2_encrypt(
    const char* content,
    const char* charset,
    const char* public_key,
    char** ciphertext_hex
);

/**
 * SM2 decryption (auto-detect format, output string)
 * @param ciphertext Ciphertext (HEX or Base64 string)
 * @param private_key Private key (supports HEX or Base64)
 * @param charset Character set (can be NULL)
 * @param plaintext_str Output plaintext string
 * @return 0 on success, negative error code on failure
 * @note Caller must call free() to release plaintext_str
 */
CROSSMOOL_API int crossmool_sm2_decrypt(
    const char* ciphertext,
    const char* private_key,
    const char* charset,
    char** plaintext_str
);

/**
 * SM2 encryption (returns byte array)
 * @param content Plaintext data
 * @param content_len Plaintext length
 * @param public_key Public key
 * @param ciphertext Output ciphertext
 * @param ciphertext_len Output ciphertext length
 * @return 0 on success, negative error code on failure
 */
CROSSMOOL_API int crossmool_sm2_encrypt_bytes(
    const unsigned char* content,
    size_t content_len,
    const char* public_key,
    unsigned char** ciphertext,
    size_t* ciphertext_len
);

/**
 * SM2 encryption (returns HEX string, byte array input)
 */
CROSSMOOL_API int crossmool_sm2_encrypt_to_hex(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* public_key,
    char** ciphertext_hex
);

/**
 * SM2 encryption (returns Base64 string, byte array input)
 */
CROSSMOOL_API int crossmool_sm2_encrypt_to_base64(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* public_key,
    char** ciphertext_base64
);

/**
 * SM2 decryption (returns byte array)
 */
CROSSMOOL_API int crossmool_sm2_decrypt_bytes(
    const char* ciphertext,
    const char* private_key,
    unsigned char** plaintext,
    size_t* plaintext_len
);

/**
 * SM2 decryption and convert to string
 */
CROSSMOOL_API int crossmool_sm2_decrypt_to_string(
    const char* ciphertext,
    const char* private_key,
    const char* charset,
    char** plaintext_str
);

/* ====================================================
 * Signing / Verification
 * ==================================================== */

/**
 * SM2 signing (auto-detect charset, output HEX string)
 * @param content Data to sign (C string)
 * @param charset Character set (can be NULL)
 * @param private_key Private key (supports HEX or Base64)
 * @param signature_hex Output HEX format signature
 * @return 0 on success, negative error code on failure
 * @note Caller must call free() to release signature_hex
 */
CROSSMOOL_API int crossmool_sm2_sign(
    const char* content,
    const char* charset,
    const char* private_key,
    char** signature_hex
);

/**
 * SM2 verification
 * @param content Original string (C string)
 * @param charset Character set (can be NULL)
 * @param signature Signature (HEX or Base64)
 * @param public_key Public key (HEX or Base64)
 * @return 1 on success, 0 on failure, negative on error
 */
CROSSMOOL_API int crossmool_sm2_verify(
    const char* content,
    const char* charset,
    const char* signature,
    const char* public_key
);

/**
 * SM2 signing (byte array input, returns byte array)
 */
CROSSMOOL_API int crossmool_sm2_sign_bytes(
    const unsigned char* content,
    size_t content_len,
    const char* private_key,
    unsigned char** signature,
    size_t* signature_len
);

/**
 * SM2 signing (byte array input, returns HEX string)
 */
CROSSMOOL_API int crossmool_sm2_sign_to_hex(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* private_key,
    char** signature_hex
);

/**
 * SM2 signing (byte array input, returns Base64 string)
 */
CROSSMOOL_API int crossmool_sm2_sign_to_base64(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* private_key,
    char** signature_base64
);

/**
 * SM2 verification (byte array input)
 */
CROSSMOOL_API int crossmool_sm2_verify_bytes(
    const unsigned char* content,
    size_t content_len,
    const char* signature,
    const char* public_key
);

/* ====================================================
 * Encrypt+Sign / Verify+Decrypt
 * ==================================================== */

/**
 * Encrypt and sign (string input, output HEX)
 * @param content Plaintext string
 * @param charset Character set (can be NULL)
 * @param enc_public_key Encryption public key
 * @param sign_private_key Signing private key
 * @param result Output ciphertext-signature pair pointer (auto-allocated)
 * @return 0 on success, negative error code on failure
 * @note Caller must call crossmool_sm2_cipher_sig_pair_free() to release memory
 */
CROSSMOOL_API int crossmool_sm2_encrypt_sign(
    const char* content,
    const char* charset,
    const char* enc_public_key,
    const char* sign_private_key,
    crossmool_sm2_cipher_sig_pair_t** result
);

/**
 * Verify and decrypt (string output)
 * @param ciphertext Ciphertext (HEX or Base64)
 * @param signature Signature (HEX or Base64)
 * @param sign_public_key Verification public key
 * @param dec_private_key Decryption private key
 * @param charset Character set (can be NULL)
 * @param plaintext Output plaintext string
 * @return 0 on success, negative error code on failure
 */
CROSSMOOL_API int crossmool_sm2_verify_decrypt(
    const char* ciphertext,
    const char* signature,
    const char* sign_public_key,
    const char* dec_private_key,
    const char* charset,
    char** plaintext
);

/**
 * Encrypt and sign (byte array input, supports HEX or Base64 output)
 * @param to_base64 0=HEX, 1=Base64
 */
CROSSMOOL_API int crossmool_sm2_encrypt_sign_ex(
    const unsigned char* content,
    size_t content_len,
    const char* charset,
    const char* enc_public_key,
    const char* sign_private_key,
    int to_base64,
    crossmool_sm2_cipher_sig_pair_t* result
);

/**
 * Free ciphertext-signature pair memory (pointer version)
 */
CROSSMOOL_API void crossmool_sm2_cipher_sig_pair_free(crossmool_sm2_cipher_sig_pair_t* pair);

/* ============================================================
 * PEM Export / Import
 * ============================================================ */

/**
 * Export public key as PEM string (X.509 SubjectPublicKeyInfo).
 * @param public_key_hex  public key in hex format (04+X+Y, 130 chars)
 * @param pem_out         output PEM string (caller must free())
 * @return 0 on success, negative on error
 */
CROSSMOOL_API int crossmool_sm2_export_public_key_pem(const char* public_key_hex, char** pem_out);

/**
 * Export private key as PEM string (PKCS#8 PrivateKeyInfo).
 * @param private_key_hex private key in hex format (64 chars)
 * @param public_key_hex  public key in hex format (to embed in PKCS#8)
 * @param pem_out         output PEM string (caller must free())
 * @return 0 on success, negative on error
 */
CROSSMOOL_API int crossmool_sm2_export_private_key_pem(const char* private_key_hex, const char* public_key_hex, char** pem_out);

/**
 * Import public key from PEM string, returning hex key (04+X+Y, 130 chars).
 * @param pem        PEM string (X.509 SubjectPublicKeyInfo)
 * @param hex_out    output hex public key (caller must free())
 * @return 0 on success, negative on error
 */
CROSSMOOL_API int crossmool_sm2_import_public_key_pem(const char* pem, char** hex_out);

/**
 * Import private key from PEM string, returning hex key (64 chars).
 * @param pem        PEM string (PKCS#8 PrivateKeyInfo)
 * @param hex_out    output hex private key (caller must free())
 * @return 0 on success, negative on error
 */
CROSSMOOL_API int crossmool_sm2_import_private_key_pem(const char* pem, char** hex_out);

#ifdef __cplusplus
}
#endif

#endif // CROSSMOOL_SM2_H