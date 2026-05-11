#include "SM4Util.h"
#include "StringUtil.h"
#include "HexUtil.h"
#include <vector>
#include <string>
#include <random>

// Conditional compilation based on GmSSL availability
#ifdef USE_GMSSL
#include <gmssl/sm4.h>
#else
// Placeholder for stub implementation
#include <cstring>
#endif

std::vector<unsigned char> SM4Util::generateKey() {
    std::vector<unsigned char> key(16); // SM4 key size is 128 bits (16 bytes)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto& byte : key) {
        byte = static_cast<unsigned char>(dis(gen));
    }

    return key;
}

std::string SM4Util::generateKeyAsHex() {
    auto key = generateKey();
    return HexUtil::encodeHexStr(key);
}

std::vector<unsigned char> SM4Util::parseHexKey(const std::string& hexKey) {
    return HexUtil::decodeHexStr(hexKey);
}

std::string SM4Util::encryptEcbNative(const std::vector<unsigned char>& key, const std::vector<unsigned char>& input) {
#ifdef USE_GMSSL
    if (key.size() != 16) {
        throw std::invalid_argument("SM4 key must be 16 bytes (128 bits)");
    }

    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, key.data());

    // PKCS7 padding: always add padding, even for block-aligned inputs
    std::vector<unsigned char> paddedInput = input;
    size_t blockSize = 16;
    size_t paddingLen = blockSize - (paddedInput.size() % blockSize);
    for (size_t i = 0; i < paddingLen; ++i) {
        paddedInput.push_back(static_cast<unsigned char>(paddingLen));
    }

    std::vector<unsigned char> output(paddedInput.size());
    size_t numBlocks = paddedInput.size() / blockSize;

    for (size_t i = 0; i < numBlocks; ++i) {
        sm4_encrypt(&sm4_key, paddedInput.data() + i * blockSize, output.data() + i * blockSize);
    }

    return HexUtil::encodeHexStr(output);
#else
    // Stub implementation for testing
    std::vector<unsigned char> output = input;

    // Simple XOR-based encryption for demonstration
    for (size_t i = 0; i < output.size(); ++i) {
        output[i] ^= key[i % key.size()];
    }

    return HexUtil::encodeHexStr(output);
#endif
}

std::string SM4Util::decryptEcbNative(const std::vector<unsigned char>& key, const std::string& hexCipherText) {
#ifdef USE_GMSSL
    if (key.size() != 16) {
        throw std::invalid_argument("SM4 key must be 16 bytes (128 bits)");
    }

    auto cipherBytes = HexUtil::decodeHexStr(hexCipherText);

    SM4_KEY sm4_key;
    sm4_set_decrypt_key(&sm4_key, key.data());

    std::vector<unsigned char> output(cipherBytes.size());
    size_t blockSize = 16;
    size_t numBlocks = cipherBytes.size() / blockSize;

    for (size_t i = 0; i < numBlocks; ++i) {
        sm4_decrypt(&sm4_key, cipherBytes.data() + i * blockSize, output.data() + i * blockSize);
    }

    // Remove PKCS7 padding if present
    if (!output.empty()) {
        unsigned char paddingByte = output.back();
        if (paddingByte <= 16) { // Maximum padding for a 16-byte block
            bool paddingValid = true;
            for (size_t i = 0; i < paddingByte; ++i) {
                if (output[output.size() - 1 - i] != paddingByte) {
                    paddingValid = false;
                    break;
                }
            }
            if (paddingValid) {
                output.resize(output.size() - paddingByte);
            }
        }
    }

    return StringUtil::bytesToString(output, "UTF-8");
#else
    // Stub implementation for testing
    auto cipherBytes = HexUtil::decodeHexStr(hexCipherText);
    std::vector<unsigned char> output = cipherBytes;

    // Reverse the simple XOR-based encryption
    for (size_t i = 0; i < output.size(); ++i) {
        output[i] ^= key[i % key.size()];
    }

    return StringUtil::bytesToString(output, "UTF-8");
#endif
}

std::string SM4Util::encryptEcbJca(const std::vector<unsigned char>& key, const std::string& plainText) {
    auto input = StringUtil::stringToBytes(plainText, "UTF-8");
    return encryptEcbNative(key, input);
}

std::string SM4Util::decryptEcbJca(const std::vector<unsigned char>& key, const std::string& hexCipherText) {
    return decryptEcbNative(key, hexCipherText);
}