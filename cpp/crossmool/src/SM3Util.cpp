#include "SM3Util.h"
#include "StringUtil.h"
#include "HexUtil.h"
#include "Base64Util.h"
#include <vector>
#include <string>
#include <random>

// Conditional compilation based on GmSSL availability
#ifdef USE_GMSSL
#include <gmssl/sm3.h>
#include <gmssl/hmac.h>
#else
// Placeholder for stub implementation
#include <cstring>
#endif

std::vector<unsigned char> SM3Util::digest(const std::vector<unsigned char>& input) {
#ifdef USE_GMSSL
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, input.data(), input.size());

    uint8_t digest[SM3_DIGEST_SIZE];
    sm3_finish(&ctx, digest);

    return std::vector<unsigned char>(digest, digest + SM3_DIGEST_SIZE);
#else
    // Stub implementation for testing purposes
    // In a real scenario, you would implement the actual SM3 algorithm
    std::vector<unsigned char> result(32); // SM3 produces 256-bit (32-byte) digests

    // Simple hash for demonstration purposes
    for (size_t i = 0; i < input.size(); ++i) {
        result[i % 32] ^= input[i];
    }

    // Add some mixing to make it more like a proper hash
    for (int i = 0; i < 32; ++i) {
        result[i] = (result[i] + i) % 256;
    }

    return result;
#endif
}

std::string SM3Util::digestToHex(const std::vector<unsigned char>& input) {
    auto digestBytes = digest(input);
    return HexUtil::encodeHexStr(digestBytes);
}

std::string SM3Util::digestToStr(const std::vector<unsigned char>& input, bool toBase64) {
    auto digestBytes = digest(input);
    if (toBase64) {
        return Base64Util::encodeBase64Str(digestBytes);
    } else {
        return HexUtil::encodeHexStr(digestBytes);
    }
}

std::string SM3Util::digestToStr(const std::string& input, const std::string& charset, bool toBase64) {
    auto inputBytes = StringUtil::stringToBytes(input, charset);
    return digestToStr(inputBytes, toBase64);
}

std::string SM3Util::digestToStr(const std::string& input) {
    return digestToStr(input, "UTF-8", false);
}

std::vector<unsigned char> SM3Util::generateHmacKey(int keyLengthInBytes) {
    if (keyLengthInBytes < 32) {
        throw std::invalid_argument("keyLengthInBytes must be >= 32");
    }

    std::vector<unsigned char> key(keyLengthInBytes);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto& byte : key) {
        byte = static_cast<unsigned char>(dis(gen));
    }

    return key;
}

std::string SM3Util::generateHmacKeyToStr(int keyLengthInBytes, bool toBase64) {
    auto key = generateHmacKey(keyLengthInBytes);
    if (toBase64) {
        return Base64Util::encodeBase64Str(key);
    } else {
        return HexUtil::encodeHexStr(key);
    }
}

std::vector<unsigned char> SM3Util::hmac(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
#ifdef USE_GMSSL
    uint8_t out[SM3_DIGEST_SIZE];
    hmac_sm3(key.data(), key.size(), data.data(), data.size(), out);
    return std::vector<unsigned char>(out, out + SM3_DIGEST_SIZE);
#else
    // Stub implementation for HMAC-SM3
    // In practice, you would implement the actual HMAC algorithm with SM3
    std::vector<unsigned char> combined;
    combined.reserve(key.size() + data.size());
    combined.insert(combined.end(), key.begin(), key.end());
    combined.insert(combined.end(), data.begin(), data.end());

    return digest(combined);
#endif
}

std::vector<unsigned char> SM3Util::hmac(const std::string& key, const std::string& data) {
    // Check if key is hex or base64
    bool isKeyHex = HexUtil::isHexString(key);
    bool isKeyBase64 = Base64Util::isBase64String(key);

    if (!isKeyHex && !isKeyBase64) {
        throw std::invalid_argument("Key for HMAC-SM3 must be Hex string or Base64 string");
    }

    auto keyBytes = isKeyHex ?
        HexUtil::decodeHexStr(key) :
        Base64Util::decodeBase64Str(key);

    // Check if data is hex or base64
    bool isDataHex = HexUtil::isHexString(data);
    bool isDataBase64 = Base64Util::isBase64String(data);

    std::vector<unsigned char> dataBytes;
    if (isDataHex) {
        dataBytes = HexUtil::decodeHexStr(data);
    } else if (isDataBase64) {
        dataBytes = Base64Util::decodeBase64Str(data);
    } else {
        // Treat as UTF-8 string
        dataBytes = StringUtil::stringToBytes(data, "UTF-8");
    }

    return hmac(keyBytes, dataBytes);
}

std::string SM3Util::hmacToStr(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data, bool toBase64) {
    auto hmacResult = hmac(key, data);
    if (toBase64) {
        return Base64Util::encodeBase64Str(hmacResult);
    } else {
        return HexUtil::encodeHexStr(hmacResult);
    }
}

std::string SM3Util::hmacToStr(const std::string& key, const std::string& data, bool toBase64) {
    auto hmacResult = hmac(key, data);
    if (toBase64) {
        return Base64Util::encodeBase64Str(hmacResult);
    } else {
        return HexUtil::encodeHexStr(hmacResult);
    }
}

bool SM3Util::hmacVerify(const std::string& key, const std::string& data, const std::string& receivedHmac) {
    auto hmacResult = hmac(key, data);

    // Check if receivedHmac is hex or base64
    bool isReceivedHmacHex = HexUtil::isHexString(receivedHmac);
    bool isReceivedHmacBase64 = Base64Util::isBase64String(receivedHmac);

    if (!isReceivedHmacHex && !isReceivedHmacBase64) {
        throw std::invalid_argument("receivedHmac should be Hex string or Base64 string");
    }

    auto receivedHmacBytes = isReceivedHmacHex ?
        HexUtil::decodeHexStr(receivedHmac) :
        Base64Util::decodeBase64Str(receivedHmac);

    if (hmacResult.size() != receivedHmacBytes.size()) {
        return false;
    }

    return std::equal(hmacResult.begin(), hmacResult.end(), receivedHmacBytes.begin());
}