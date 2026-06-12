#include "SM4Util.h"
#include "StringUtil.h"
#include "HexUtil.h"
#include "Base64Util.h"
#include <vector>
#include <string>
#include <random>

#ifdef USE_GMSSL
#include <gmssl/sm4.h>
#include <gmssl/aead.h>
#else
#include <cstring>
#endif

static const size_t GCM_IV_SIZE = 12;
static const size_t GCM_TAG_SIZE = 16;

std::vector<unsigned char> SM4Util::generateKey() {
    std::vector<unsigned char> key(16);
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

std::string SM4Util::encryptGcm(const std::vector<unsigned char>& key, const std::vector<unsigned char>& input, bool toBase64) {
#ifdef USE_GMSSL
    if (key.size() != 16) {
        throw std::invalid_argument("SM4 key must be 16 bytes (128 bits)");
    }

    /* 生成随机 IV */
    std::vector<unsigned char> iv(GCM_IV_SIZE);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& b : iv) {
        b = static_cast<unsigned char>(dis(gen));
    }

    /* GCM 加密 */
    std::vector<unsigned char> ciphertext(input.size());
    unsigned char tag[GCM_TAG_SIZE];

    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, key.data());

    int ret = sm4_gcm_encrypt(
        &sm4_key,
        iv.data(), iv.size(),
        NULL, 0,
        input.data(), input.size(),
        ciphertext.data(),
        GCM_TAG_SIZE,
        tag
    );

    if (ret != 1) {
        throw std::runtime_error("SM4 GCM encryption failed");
    }

    /* 组合: IV(12) + 密文 + Tag(16) */
    std::vector<unsigned char> combined;
    combined.reserve(iv.size() + ciphertext.size() + GCM_TAG_SIZE);
    combined.insert(combined.end(), iv.begin(), iv.end());
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());
    combined.insert(combined.end(), tag, tag + GCM_TAG_SIZE);

    if (toBase64) {
        return Base64Util::encodeBase64Str(combined);
    }
    return HexUtil::encodeHexStr(combined);
#else
    /* Stub implementation */
    std::vector<unsigned char> output = input;
    for (size_t i = 0; i < output.size(); ++i) {
        output[i] ^= key[i % key.size()];
    }
    if (toBase64) {
        return Base64Util::encodeBase64Str(output);
    }
    return HexUtil::encodeHexStr(output);
#endif
}

std::vector<unsigned char> SM4Util::decryptGcm(const std::vector<unsigned char>& key, const std::string& ciphertextEncoded) {
#ifdef USE_GMSSL
    if (key.size() != 16) {
        throw std::invalid_argument("SM4 key must be 16 bytes (128 bits)");
    }

    /* 自动检测 Hex 或 Base64 */
    std::vector<unsigned char> combined;
    if (HexUtil::isHexString(ciphertextEncoded)) {
        combined = HexUtil::decodeHexStr(ciphertextEncoded);
    } else if (Base64Util::isBase64String(ciphertextEncoded)) {
        combined = Base64Util::decodeBase64Str(ciphertextEncoded);
    } else {
        throw std::invalid_argument("ciphertext must be Hex or Base64 encoded string");
    }

    if (combined.size() < GCM_IV_SIZE + GCM_TAG_SIZE) {
        throw std::runtime_error("Invalid GCM ciphertext: too short");
    }

    /* 拆分 IV、密文、Tag */
    std::vector<unsigned char> iv(combined.begin(), combined.begin() + GCM_IV_SIZE);
    size_t ciphertextLen = combined.size() - GCM_IV_SIZE - GCM_TAG_SIZE;
    std::vector<unsigned char> ciphertext(combined.begin() + GCM_IV_SIZE, combined.begin() + GCM_IV_SIZE + ciphertextLen);
    std::vector<unsigned char> tag(combined.begin() + GCM_IV_SIZE + ciphertextLen, combined.end());

    /* GCM 解密 */
    std::vector<unsigned char> plaintext(ciphertextLen > 0 ? ciphertextLen : 1);

    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, key.data());

    int ret = sm4_gcm_decrypt(
        &sm4_key,
        iv.data(), iv.size(),
        NULL, 0,
        ciphertext.data(), ciphertext.size(),
        tag.data(), tag.size(),
        plaintext.data()
    );

    if (ret != 1) {
        throw std::runtime_error("SM4 GCM decryption failed (authentication failed)");
    }

    plaintext.resize(ciphertextLen);
    return plaintext;
#else
    /* Stub implementation */
    std::vector<unsigned char> combined;
    if (HexUtil::isHexString(ciphertextEncoded)) {
        combined = HexUtil::decodeHexStr(ciphertextEncoded);
    } else {
        combined = Base64Util::decodeBase64Str(ciphertextEncoded);
    }
    std::vector<unsigned char> output = combined;
    for (size_t i = 0; i < output.size(); ++i) {
        output[i] ^= key[i % key.size()];
    }
    return output;
#endif
}

std::string SM4Util::encryptGcmString(const std::vector<unsigned char>& key, const std::string& plainText) {
    auto input = StringUtil::stringToBytes(plainText, "UTF-8");
    return encryptGcm(key, input);
}

std::string SM4Util::decryptGcmToString(const std::vector<unsigned char>& key, const std::string& ciphertextBase64) {
    auto plaintext = decryptGcm(key, ciphertextBase64);
    return StringUtil::bytesToString(plaintext, "UTF-8");
}
