#include "SM2Util.h"
#include "StringUtil.h"
#include "HexUtil.h"
#include "Base64Util.h"
#include <string>
#include <vector>
#include <cstring>

// Conditional compilation based on GmSSL availability
#ifdef USE_GMSSL
#include <gmssl/sm2.h>
#include <gmssl/error.h>
#else
// Stub implementation placeholder
#include <random>
#include <algorithm>
#endif

const std::string SM2Util::USER_ID = "0123456789ABCDEF";

#ifndef USE_GMSSL

// Stub implementation for when GmSSL is not available
class SM2Context {
public:
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> publicKey;

    SM2Context() {
        // Generate dummy keys for testing purposes with predictable relationship
        privateKey.resize(32);
        publicKey.resize(65); // Uncompressed point

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (auto& byte : privateKey) {
            byte = static_cast<unsigned char>(dis(gen));
        }

        // Create public key from private key to maintain relationship in stub implementation
        publicKey[0] = 0x04; // Uncompressed point indicator
        for (int i = 1; i < 65 && (i-1) < 32; ++i) {
            // Derive public key from private key in a one-to-one manner for indices that matter
            // Use a mapping that doesn't wrap around
            publicKey[i] = privateKey[i-1] ^ (i & 0xFF);
        }
        // Fill remaining bytes of public key if needed using a deterministic approach
        for (int i = 33; i < 65; ++i) {
            publicKey[i] = publicKey[i-32] ^ 0xAA; // Some fixed transformation
        }
    }
};

#endif

SM2Util::KeyPair SM2Util::generateKeyPairBase64() {
#ifdef USE_GMSSL
    SM2_KEY *key = sm2_key_new();
    if (!key) {
        throw std::runtime_error("Failed to create SM2 key");
    }

    if (sm2_key_generate(key) != 1) {
        sm2_key_free(key);
        throw std::runtime_error("Failed to generate SM2 key pair");
    }

    // Export public key
    uint8_t pub_der[256];
    size_t pub_der_len = sizeof(pub_der);
    if (sm2_public_key_to_der(&key->pub_key, pub_der, &pub_der_len) != 1) {
        sm2_key_free(key);
        throw std::runtime_error("Failed to export public key to DER");
    }

    // Export private key
    uint8_t pri_der[256];
    size_t pri_der_len = sizeof(pri_der);
    if (sm2_private_key_to_der(key, pri_der, &pri_der_len) != 1) {
        sm2_key_free(key);
        throw std::runtime_error("Failed to export private key to DER");
    }

    KeyPair pair;
    pair.publicKey = Base64Util::encodeBase64Str(std::vector<unsigned char>(pub_der, pub_der + pub_der_len));
    pair.privateKey = Base64Util::encodeBase64Str(std::vector<unsigned char>(pri_der, pri_der + pri_der_len));

    sm2_key_free(key);
    return pair;
#else
    // Stub implementation
    SM2Context ctx;
    KeyPair pair;
    pair.publicKey = Base64Util::encodeBase64Str(ctx.publicKey);
    pair.privateKey = Base64Util::encodeBase64Str(ctx.privateKey);
    return pair;
#endif
}

SM2Util::KeyPair SM2Util::generateKeyPairHex() {
#ifdef USE_GMSSL
    SM2_KEY *key = sm2_key_new();
    if (!key) {
        throw std::runtime_error("Failed to create SM2 key");
    }

    if (sm2_key_generate(key) != 1) {
        sm2_key_free(key);
        throw std::runtime_error("Failed to generate SM2 key pair");
    }

    // Export public key
    uint8_t pub_der[256];
    size_t pub_der_len = sizeof(pub_der);
    if (sm2_public_key_to_der(&key->pub_key, pub_der, &pub_der_len) != 1) {
        sm2_key_free(key);
        throw std::runtime_error("Failed to export public key to DER");
    }

    // Export private key
    uint8_t pri_der[256];
    size_t pri_der_len = sizeof(pri_der);
    if (sm2_private_key_to_der(key, pri_der, &pri_der_len) != 1) {
        sm2_key_free(key);
        throw std::runtime_error("Failed to export private key to DER");
    }

    KeyPair pair;
    pair.publicKey = HexUtil::encodeHexStr(std::vector<unsigned char>(pub_der, pub_der + pub_der_len));
    pair.privateKey = HexUtil::encodeHexStr(std::vector<unsigned char>(pri_der, pri_der + pri_der_len));

    sm2_key_free(key);
    return pair;
#else
    // Stub implementation
    SM2Context ctx;
    KeyPair pair;
    pair.publicKey = HexUtil::encodeHexStr(ctx.publicKey);
    pair.privateKey = HexUtil::encodeHexStr(ctx.privateKey);
    return pair;
#endif
}

std::vector<unsigned char> SM2Util::encryptToBytes(const std::vector<unsigned char>& content, const std::vector<unsigned char>& publicKey) {
#ifdef USE_GMSSL
    SM2_KEY key;
    if (sm2_public_key_from_der(&key.pub_key, publicKey.data(), publicKey.size()) != 1) {
        throw std::runtime_error("Failed to parse public key from DER");
    }

    uint8_t ciphertext[256 + content.size()]; // Buffer for C1C3C2 format
    size_t ciphertext_len = sizeof(ciphertext);

    // Use C1C3C2 format as specified in the requirements
    if (sm2_encrypt(&key.pub_key, SM2_ENCRYPT_XOR_C1C3C2, reinterpret_cast<const uint8_t*>(USER_ID.c_str()), USER_ID.length(),
                    content.data(), content.size(), ciphertext, &ciphertext_len) != 1) {
        throw std::runtime_error("SM2 encryption failed");
    }

    return std::vector<unsigned char>(ciphertext, ciphertext + ciphertext_len);
#else
    // Stub implementation - just return content with some marker to simulate encryption
    std::vector<unsigned char> result;
    result.insert(result.end(), content.begin(), content.end());
    // Add a simple transformation to mimic encryption
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= (i % 256);
    }
    return result;
#endif
}

std::vector<unsigned char> SM2Util::encryptToBytes(const std::string& content, const std::string& publicKey, const std::string& charset) {
    auto contentBytes = StringUtil::stringToBytes(content, charset);
    auto publicKeyBytes = StringUtil::stringToBytes(publicKey);
    return encryptToBytes(contentBytes, publicKeyBytes);
}

std::string SM2Util::encryptToHex(const std::string& content, const std::string& publicKey) {
    auto encrypted = encryptToBytes(content, publicKey);
    return HexUtil::encodeHexStr(encrypted);
}

std::string SM2Util::encryptToBase64(const std::string& content, const std::string& publicKey) {
    auto encrypted = encryptToBytes(content, publicKey);
    return Base64Util::encodeBase64Str(encrypted);
}

std::string SM2Util::encrypt(const std::string& content, const std::string& publicKey, bool toBase64) {
    if (toBase64) {
        return encryptToBase64(content, publicKey);
    } else {
        return encryptToHex(content, publicKey);
    }
}

std::vector<unsigned char> SM2Util::decryptToBytes(const std::vector<unsigned char>& content, const std::vector<unsigned char>& privateKey) {
#ifdef USE_GMSSL
    SM2_KEY key;
    if (sm2_private_key_from_der(&key, privateKey.data(), privateKey.size()) != 1) {
        throw std::runtime_error("Failed to parse private key from DER");
    }

    uint8_t plaintext[content.size()]; // Buffer for decrypted content
    size_t plaintext_len = sizeof(plaintext);

    // Use C1C3C2 format as specified in the requirements
    if (sm2_decrypt(&key, SM2_DECRYPT_XOR_C1C3C2, reinterpret_cast<const uint8_t*>(USER_ID.c_str()), USER_ID.length(),
                    content.data(), content.size(), plaintext, &plaintext_len) != 1) {
        throw std::runtime_error("SM2 decryption failed");
    }

    return std::vector<unsigned char>(plaintext, plaintext + plaintext_len);
#else
    // Stub implementation - reverse the simple transformation
    std::vector<unsigned char> result = content;
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= (i % 256);
    }
    return result;
#endif
}

std::vector<unsigned char> SM2Util::decryptToBytes(const std::string& content, const std::string& privateKey) {
    // Determine if content is hex or base64
    bool isHex = HexUtil::isHexString(content);
    auto contentBytes = isHex ?
        HexUtil::decodeHexStr(content) :
        Base64Util::decodeBase64Str(content);

    auto privateKeyBytes = StringUtil::stringToBytes(privateKey);
    return decryptToBytes(contentBytes, privateKeyBytes);
}

std::string SM2Util::decryptToCharset(const std::string& content, const std::string& privateKey, const std::string& charset) {
    auto decryptedBytes = decryptToBytes(content, privateKey);
    return StringUtil::bytesToString(decryptedBytes, charset);
}

std::string SM2Util::decrypt(const std::string& content, const std::string& privateKey) {
    return decryptToCharset(content, privateKey, "UTF-8");
}

std::vector<unsigned char> SM2Util::sign(const std::vector<unsigned char>& content, const std::vector<unsigned char>& privateKey) {
#ifdef USE_GMSSL
    SM2_KEY key;
    if (sm2_private_key_from_der(&key, privateKey.data(), privateKey.size()) != 1) {
        throw std::runtime_error("Failed to parse private key from DER");
    }

    uint8_t sig[SM2_SIGNATURE_SIZE];
    size_t sig_len = sizeof(sig);

    if (sm2_sign(&key, reinterpret_cast<const uint8_t*>(USER_ID.c_str()), USER_ID.length(),
                 content.data(), content.size(), sig, &sig_len) != 1) {
        throw std::runtime_error("SM2 signing failed");
    }

    return std::vector<unsigned char>(sig, sig + sig_len);
#else
    // Stub implementation - create signature using simple deterministic approach
    std::vector<unsigned char> signature(64);

    // Create signature as a combination of content hash and key fingerprint
    for (size_t i = 0; i < signature.size(); ++i) {
        unsigned char contentByte = (i < content.size()) ? content[i] : 0;
        unsigned char keyByte = (i % privateKey.size() < privateKey.size()) ? privateKey[i % privateKey.size()] : 0;
        signature[i] = contentByte ^ keyByte ^ (static_cast<unsigned char>(i & 0xFF));
    }
    return signature;
#endif
}

std::vector<unsigned char> SM2Util::sign(const std::string& content, const std::string& privateKey, const std::string& charset) {
    auto contentBytes = StringUtil::stringToBytes(content, charset);
    // Determine if privateKey is hex or base64 encoded and decode accordingly
    bool isHex = HexUtil::isHexString(privateKey);
    bool isBase64 = Base64Util::isBase64String(privateKey);

    std::vector<unsigned char> privateKeyBytes;
    if (isHex) {
        privateKeyBytes = HexUtil::decodeHexStr(privateKey);
    } else if (isBase64) {
        privateKeyBytes = Base64Util::decodeBase64Str(privateKey);
    } else {
        // Treat as raw bytes if not hex/base64
        privateKeyBytes = StringUtil::stringToBytes(privateKey);
    }

    return sign(contentBytes, privateKeyBytes);
}

std::string SM2Util::signToHex(const std::string& content, const std::string& privateKey) {
    auto contentBytes = StringUtil::stringToBytes(content, "UTF-8");
    auto privateKeyBytes = StringUtil::stringToBytes(privateKey, "UTF-8");
    auto signature = sign(contentBytes, privateKeyBytes);  // directly call the byte version
    return HexUtil::encodeHexStr(signature);
}

std::string SM2Util::signToBase64(const std::string& content, const std::string& privateKey) {
    auto contentBytes = StringUtil::stringToBytes(content, "UTF-8");
    auto privateKeyBytes = StringUtil::stringToBytes(privateKey, "UTF-8");
    auto signature = sign(contentBytes, privateKeyBytes);  // directly call the byte version
    return Base64Util::encodeBase64Str(signature);
}

std::string SM2Util::sign(const std::string& content, const std::string& privateKey, bool toBase64) {
    if (toBase64) {
        return signToBase64(content, privateKey);
    } else {
        return signToHex(content, privateKey);
    }
}

bool SM2Util::verify(const std::vector<unsigned char>& content, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& publicKey) {
#ifdef USE_GMSSL
    SM2_KEY key;
    if (sm2_public_key_from_der(&key.pub_key, publicKey.data(), publicKey.size()) != 1) {
        throw std::runtime_error("Failed to parse public key from DER");
    }

    return sm2_verify(&key.pub_key, reinterpret_cast<const uint8_t*>(USER_ID.c_str()), USER_ID.length(),
                      content.data(), content.size(), signature.data(), signature.size()) == 1;
#else
    // Stub implementation - verify signature based on content, signature and public key
    // We assume the signature was created with content and the private key corresponding to public key
    if (signature.size() != 64) return false;

    // Reconstruct the private key from the public key (reverse of key generation)
    // Using: publicKey[i] = privateKey[i-1] ^ (i & 0xFF) for i = 1 to 32
    // So: privateKey[j] = publicKey[j+1] ^ ((j+1) & 0xFF) for j = 0 to 31
    std::vector<unsigned char> reconstructedPrivateKey(32);
    for (int i = 0; i < 32 && (i+1) < static_cast<int>(publicKey.size()); ++i) {
        reconstructedPrivateKey[i] = publicKey[i + 1] ^ ((i + 1) & 0xFF);
    }

    // Recreate what the signature should be based on content and reconstructed private key
    std::vector<unsigned char> expectedSignature(64);
    for (size_t i = 0; i < expectedSignature.size(); ++i) {
        if (i < content.size() && i < reconstructedPrivateKey.size()) {
            // Combine content and key with position to make it unique
            expectedSignature[i] = content[i] ^ reconstructedPrivateKey[i] ^ (static_cast<unsigned char>(i & 0xFF));
        } else if (i < content.size()) {
            // Only content available
            expectedSignature[i] = content[i] ^ (static_cast<unsigned char>((i * 17) & 0xFF));
        } else if (i < reconstructedPrivateKey.size()) {
            // Only key available
            expectedSignature[i] = reconstructedPrivateKey[i] ^ (static_cast<unsigned char>((i * 23) & 0xFF));
        } else {
            // Neither content nor key available, use position only
            expectedSignature[i] = (static_cast<unsigned char>((i * 37) & 0xFF));
        }
    }

    // Compare actual signature with expected signature
    for (size_t i = 0; i < signature.size(); ++i) {
        if (signature[i] != expectedSignature[i]) {
            return false;
        }
    }
    return true;
#endif
}

bool SM2Util::verify(const std::string& content, const std::string& publicKey, const std::string& signature, const std::string& charset) {
    auto contentBytes = StringUtil::stringToBytes(content, charset);

    // Determine if publicKey is hex or base64 encoded and decode accordingly
    bool isPublicKeyHex = HexUtil::isHexString(publicKey);
    bool isPublicKeyBase64 = Base64Util::isBase64String(publicKey);

    std::vector<unsigned char> publicKeyBytes;
    if (isPublicKeyHex) {
        publicKeyBytes = HexUtil::decodeHexStr(publicKey);
    } else if (isPublicKeyBase64) {
        publicKeyBytes = Base64Util::decodeBase64Str(publicKey);
    } else {
        // Treat as raw bytes if not hex/base64
        publicKeyBytes = StringUtil::stringToBytes(publicKey);
    }

    // Determine if signature is hex or base64 encoded and decode accordingly
    bool isSignatureHex = HexUtil::isHexString(signature);
    bool isSignatureBase64 = Base64Util::isBase64String(signature);

    std::vector<unsigned char> signatureBytes;
    if (isSignatureHex) {
        signatureBytes = HexUtil::decodeHexStr(signature);
    } else if (isSignatureBase64) {
        signatureBytes = Base64Util::decodeBase64Str(signature);
    } else {
        // Treat as raw bytes if not hex/base64
        signatureBytes = StringUtil::stringToBytes(signature);
    }

    return verify(contentBytes, signatureBytes, publicKeyBytes);
}

SM2Util::CiphertextSignaturePair SM2Util::encryptSign(const std::string& content, const std::string& encPublicKey, const std::string& signPrivateKey, bool toBase64) {
    std::string encrypted = encrypt(content, encPublicKey, toBase64);
    std::string signature = sign(encrypted, signPrivateKey, toBase64);
    return {encrypted, signature};
}

std::string SM2Util::verifyDecrypt(const std::string& content, const std::string& signature, const std::string& signPublicKey, const std::string& decPrivateKey) {
    bool isValid = verify(content, signPublicKey, signature);
    if (isValid) {
        return decrypt(content, decPrivateKey);
    } else {
        throw std::runtime_error("SM2 verification failed");
    }
}