#ifndef SM2UTIL_H
#define SM2UTIL_H

#include "crossmool_config.h"
#include <string>
#include <vector>

// SM2 signature max size (DER encoded, from GmSSL)
#define SM2_SIGNATURE_DER_MAX_SIZE 72

class CROSSMOOL_API SM2Util {
private:
    static const std::string USER_ID;

public:
    // Key pair structure similar to Java implementation
    struct KeyPair {
        std::string publicKey;
        std::string privateKey;
    };

    // Result pair for encryption + signature
    struct CiphertextSignaturePair {
        std::string ciphertext;
        std::string signature;
    };

    /**
     * Generate SM2 key pair and return as Base64 encoded strings
     */
    static KeyPair generateKeyPairBase64();

    /**
     * Generate SM2 key pair and return as Hex encoded strings
     */
    static KeyPair generateKeyPairHex();

    /**
     * Generate SM2 key pair and return as DER-encoded Hex strings.
     * Public key: Hex of X.509 SubjectPublicKeyInfo DER.
     * Private key: Hex of PKCS#8 PrivateKeyInfo DER.
     * These are the standard interchange formats compatible with Go/Rust/Java.
     */
    static KeyPair generateKeyPairRaw();

    /**
     * Encrypt data with public key (raw bytes), return as byte array
     */
    static std::vector<unsigned char> encryptToBytes(const std::vector<unsigned char>& content, const std::vector<unsigned char>& publicKey);

    /**
     * Encrypt string with public key using specified charset, return as byte array
     */
    static std::vector<unsigned char> encryptToBytes(const std::string& content, const std::string& publicKey, const std::string& charset = "UTF-8");

    /**
     * Encrypt string with public key and return as hex string
     */
    static std::string encryptToHex(const std::string& content, const std::string& publicKey);

    /**
     * Encrypt string with public key and return as base64 string
     */
    static std::string encryptToBase64(const std::string& content, const std::string& publicKey);

    /**
     * Encrypt string with public key and return as either hex or base64
     */
    static std::string encrypt(const std::string& content, const std::string& publicKey, bool toBase64 = false);

    /**
     * Decrypt byte array with private key (raw bytes), return as byte array
     */
    static std::vector<unsigned char> decryptToBytes(const std::vector<unsigned char>& content, const std::vector<unsigned char>& privateKey);

    /**
     * Decrypt string (hex/base64 format) with private key, return as byte array
     */
    static std::vector<unsigned char> decryptToBytes(const std::string& content, const std::string& privateKey);

    /**
     * Decrypt string (hex/base64 format) with private key, return as string with specified charset
     */
    static std::string decryptToCharset(const std::string& content, const std::string& privateKey, const std::string& charset = "UTF-8");

    /**
     * Main decrypt method returning UTF-8 string
     */
    static std::string decrypt(const std::string& content, const std::string& privateKey);

    /**
     * Sign byte array with private key (raw bytes), return as byte array
     */
    static std::vector<unsigned char> sign(const std::vector<unsigned char>& content, const std::vector<unsigned char>& privateKey);

    /**
     * Sign string with private key using specified charset, return as byte array
     */
    static std::vector<unsigned char> sign(const std::string& content, const std::string& privateKey, const std::string& charset = "UTF-8");

    /**
     * Sign string with private key and return as hex string
     */
    static std::string signToHex(const std::string& content, const std::string& privateKey);

    /**
     * Sign string with private key and return as base64 string
     */
    static std::string signToBase64(const std::string& content, const std::string& privateKey);

    /**
     * Sign string with private key and return as either hex or base64
     */
    static std::string sign(const std::string& content, const std::string& privateKey, bool toBase64 = false);

    /**
     * Verify signature for byte array content with public key (raw bytes)
     */
    static bool verify(const std::vector<unsigned char>& content, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& publicKey);

    /**
     * Verify signature for string content with public key using specified charset
     */
    static bool verify(const std::string& content, const std::string& publicKey, const std::string& signature, const std::string& charset = "UTF-8");

    /**
     * Encrypt and sign content, returning both ciphertext and signature
     */
    static CiphertextSignaturePair encryptSign(const std::string& content, const std::string& encPublicKey, const std::string& signPrivateKey, bool toBase64 = false);

    /**
     * Verify signature and decrypt content
     */
    static std::string verifyDecrypt(const std::string& content, const std::string& signature, const std::string& signPublicKey, const std::string& decPrivateKey);

    // ── PEM Export/Import ──

    /**
     * Encode DER bytes to PEM string.
     * @param der  DER-encoded key bytes in hex format
     * @param type PEM label ("PUBLIC KEY" or "PRIVATE KEY")
     */
    static std::string exportKeyPem(const std::string& derHex, const std::string& type);

    /**
     * Decode PEM string to DER hex.
     * @param pem  PEM-encoded key
     * @param type expected PEM label
     * @return DER bytes in hex format
     */
    static std::string importKeyPem(const std::string& pem, const std::string& type);
};

#endif // SM2UTIL_H
