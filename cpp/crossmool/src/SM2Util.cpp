#include "SM2Util.h"
#include "StringUtil.h"
#include "HexUtil.h"
#include "Base64Util.h"
#include <string>
#include <vector>
#include <cstring>
#include <cstdio>
#include <stdexcept>

// Conditional compilation based on GmSSL availability
#ifdef USE_GMSSL
/* 禁用 GmSSL 的 error_print()/fprintf(stderr) 宏，
 * 避免 DLL 与 EXE 使用不同 CRT 实例时 stderr 为 NULL 导致崩溃 */
#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG 0
#include <gmssl/sm2.h>
#include <gmssl/error.h>
#else
// Stub implementation placeholder
#include <random>
#include <algorithm>
#endif

const std::string SM2Util::USER_ID = "1234567812345678";

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
        std::mt::19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (auto& byte : privateKey) {
            byte = static_cast<unsigned char>(dis(gen));
        }

        // Create public key from private key to maintain relationship in stub implementation
        publicKey[0] = 0x04; // Uncompressed point indicator
        for (int i = 1; i < 65 && (i-1) < 32; ++i) {
            publicKey[i] = privateKey[i-1] ^ (i & 0xFF);
        }
        for (int i = 33; i < 65; ++i) {
            publicKey[i] = publicKey[i-32] ^ 0xAA;
        }
    }
};

#endif /* !USE_GMSSL */

/* ============================================================
 * 内部辅助：解码公钥字节数组 → SM2_POINT
 * 支持：
 *   - 65 字节非压缩格式（04||x||y）
 *   - 64 字节裸格式（x||y）
 *   - X.509 SubjectPublicKeyInfo DER/ASN.1 编码
 *   - ECPrivateKey DER（提取其中的公钥部分）
 * 参考: C 项目 sm2.c decode_public_key_to_point()
 * ============================================================ */
#ifdef USE_GMSSL
static int decodePublicKeyToPoint(const uint8_t* keyBytes, size_t keyLen, SM2_POINT* point)
{
    if (keyLen == 65 && keyBytes[0] == 0x04) {
        /* 65 字节非压缩格式：04 || x[32] || y[32] */
        memcpy(point->x, keyBytes + 1, 32);
        memcpy(point->y, keyBytes + 1 + 32, 32);
        return 1;
    } else if (keyLen == 64) {
        /* 64 字节裸格式：x[32] || y[32] */
        memcpy(point->x, keyBytes, 32);
        memcpy(point->y, keyBytes + 32, 32);
        return 1;
    } else if (keyLen > 65) {
        /* 可能是 X.509 SubjectPublicKeyInfo DER 编码 */
        const uint8_t* p = keyBytes;
        size_t len = keyLen;
        SM2_KEY sm2_key;
        memset(&sm2_key, 0, sizeof(sm2_key));
        int ret = sm2_public_key_info_from_der(&sm2_key, &p, &len);
        if (ret == 1) {
            memcpy(point, &sm2_key.public_key, sizeof(SM2_POINT));
            return 1;
        }
        /* 尝试 ECPrivateKey DER 格式（从中提取公钥） */
        p = keyBytes;
        len = keyLen;
        memset(&sm2_key, 0, sizeof(sm2_key));
        ret = sm2_private_key_from_der(&sm2_key, &p, &len);
        if (ret == 1) {
            memcpy(point, &sm2_key.public_key, sizeof(SM2_POINT));
            return 1;
        }
        return 0;
    }
    return 0;
}

/* ============================================================
 * 内部辅助：将 Java/BouncyCastle 的 RAW C1C3C2 格式密文转换为 GmSSL 的 DER SEQUENCE 格式
 *
 * Java SM2Engine(C1C3C2) 输出格式: 04 || x[32] || y[32] || C3[32] || C2[N]
 * GmSSL sm2_decrypt 期望格式:
 *   SM2Cipher ::= SEQUENCE {
 *       XCoordinate  INTEGER,
 *       YCoordinate  INTEGER,
 *       HASH         OCTET STRING SIZE(32),
 *       CipherText   OCTET STRING }
 *
 * 返回值由调用方负责 free（使用 std::vector 自带管理）。
 * 移植自 C 项目 sm2.c sm2_raw_c1c3c2_to_der()。
 * ============================================================ */
static std::vector<uint8_t> sm2_raw_c1c3c2_to_der(const uint8_t* raw, size_t raw_len)
{
    if (raw_len < 1 + 32 + 32 + 32 + 1 || raw[0] != 0x04) {
        throw std::runtime_error("Invalid RAW C1C3C2 ciphertext format");
    }

    const uint8_t* x  = raw + 1;
    const uint8_t* y  = raw + 1 + 32;
    const uint8_t* c3 = raw + 1 + 64;
    const uint8_t* c2 = raw + 1 + 96;
    size_t c2_len = raw_len - (1 + 32 + 32 + 32);

    /* --- 编码 INTEGER x --- */
    size_t xi = 0;
    while (xi < 31 && x[xi] == 0x00) xi++;
    const uint8_t* xv = x + xi;
    size_t xv_len = 32 - xi;
    int x_pad = (xv[0] & 0x80) ? 1 : 0;
    size_t int_x_len = 2 + x_pad + xv_len;

    /* --- 编码 INTEGER y --- */
    size_t yi = 0;
    while (yi < 31 && y[yi] == 0x00) yi++;
    const uint8_t* yv = y + yi;
    size_t yv_len = 32 - yi;
    int y_pad = (yv[0] & 0x80) ? 1 : 0;
    size_t int_y_len = 2 + y_pad + yv_len;

    /* --- 编码 OCTET STRING c3 (固定 32 字节) --- */
    size_t oct_c3_len = 2 + 32;

    /* --- 编码 OCTET STRING c2 --- */
    size_t oct_c2_hdr = 2;
    if (c2_len >= 128) oct_c2_hdr = 3;
    if (c2_len >= 256) oct_c2_hdr = 4;
    size_t oct_c2_len = oct_c2_hdr + c2_len;

    /* --- 计算 SEQUENCE 内部长度 --- */
    size_t inner_len = int_x_len + int_y_len + oct_c3_len + oct_c2_len;

    /* --- 计算 SEQUENCE 头部长度 --- */
    size_t seq_hdr = 2;
    if (inner_len >= 128) seq_hdr = 3;
    if (inner_len >= 256) seq_hdr = 4;

    size_t total = seq_hdr + inner_len;
    std::vector<uint8_t> out(total);
    uint8_t* p = out.data();

    /* SEQUENCE header */
    *p++ = 0x30;
    if (inner_len < 128) {
        *p++ = (uint8_t)inner_len;
    } else if (inner_len < 256) {
        *p++ = 0x81; *p++ = (uint8_t)inner_len;
    } else {
        *p++ = 0x82;
        *p++ = (uint8_t)(inner_len >> 8);
        *p++ = (uint8_t)(inner_len & 0xff);
    }

    /* INTEGER x */
    *p++ = 0x02;
    *p++ = (uint8_t)(x_pad + xv_len);
    if (x_pad) *p++ = 0x00;
    memcpy(p, xv, xv_len); p += xv_len;

    /* INTEGER y */
    *p++ = 0x02;
    *p++ = (uint8_t)(y_pad + yv_len);
    if (y_pad) *p++ = 0x00;
    memcpy(p, yv, yv_len); p += yv_len;

    /* OCTET STRING c3 (32 bytes) */
    *p++ = 0x04; *p++ = 32;
    memcpy(p, c3, 32); p += 32;

    /* OCTET STRING c2 */
    *p++ = 0x04;
    if (c2_len < 128) {
        *p++ = (uint8_t)c2_len;
    } else if (c2_len < 256) {
        *p++ = 0x81; *p++ = (uint8_t)c2_len;
    } else {
        *p++ = 0x82;
        *p++ = (uint8_t)(c2_len >> 8);
        *p++ = (uint8_t)(c2_len & 0xff);
    }
    memcpy(p, c2, c2_len);

    return out;
}

/* ============================================================
 * 内部辅助：解码私钥字节数组 → SM2_KEY
 * 支持：
 *   - 32 字节原始私钥（自动重建公钥）
 *   - PKCS#8 PrivateKeyInfo DER 编码
 *   - ECPrivateKey DER 编码（RFC 5915，含或不含 [0] params）
 *
 * 注意：GmSSL 的 sm2_private_key_info_from_der 要求内层 ECPrivateKey
 * 必须包含 [0] EXPLICIT parameters。对于缺少此字段的密钥，需要直接
 * 调用 sm2_private_key_from_der 并手动补充公钥。
 * ============================================================ */
static int decodePrivateKeyToKey(const uint8_t* keyBytes, size_t keyLen, SM2_KEY* key)
{
    memset(key, 0, sizeof(SM2_KEY));

    if (keyLen == 32) {
        /* 32 字节原始私钥 */
        memcpy(key->private_key, keyBytes, 32);
        return sm2_key_set_private_key(key, keyBytes); // 同时重建公钥
    } else if (keyLen > 32) {
        /* 尝试 PKCS#8 PrivateKeyInfo DER 编码 */
        const uint8_t* p = keyBytes;
        size_t len = keyLen;
        const uint8_t* attrs = NULL;
        size_t attrslen = 0;
        int ret = sm2_private_key_info_from_der(key, &attrs, &attrslen, &p, &len);
        if (ret == 1) {
            return 1;
        }

        /* 尝试 ECPrivateKey (RFC 5915) DER 格式（无外层 PKCS#8 包装） */
        p = keyBytes;
        len = keyLen;
        memset(key, 0, sizeof(SM2_KEY));
        ret = sm2_private_key_from_der(key, &p, &len);
        if (ret == 1) {
            return 1;
        }

        /* 对于缺少 [0] params 但包含 [1] public key 的 ECPrivateKey，
         * sm2_private_key_from_der 会失败。手动提取私钥字节并用 sm2_key_set_private_key 重建公钥。
         *
         * ECPrivateKey ::= SEQUENCE {
         *   version    INTEGER { v1(1) },
         *   privateKey OCTET STRING,
         *   parameters [0] EXPLICIT ECParameters OPTIONAL,  -- 可选
         *   publicKey  [1] EXPLICIT BIT STRING OPTIONAL        -- 可选
         * }
         */
        if (keyLen > 35 && keyBytes[0] == 0x30) {
            const uint8_t* pp = keyBytes;
            size_t remaining = keyLen;

            /* 解析外层 SEQUENCE */
            if (remaining < 2 || pp[0] != 0x30) return 0;
            pp++; remaining--;
            size_t seq_len;
            if (pp[0] < 0x80) { seq_len = pp[0]; pp++; remaining--; }
            else if (pp[0] == 0x81) { seq_len = pp[1]; pp += 2; remaining -= 2; }
            else if (pp[0] == 0x82) { seq_len = (size_t(pp[1]) << 8) | pp[2]; pp += 3; remaining -= 3; }
            else return 0;

            /* 跳过 version INTEGER */
            if (remaining < 3 || pp[0] != 0x02) return 0;
            size_t ver_len = pp[1];
            pp += 2 + ver_len; remaining -= 2 + ver_len;

            /* 提取 privateKey OCTET STRING */
            if (remaining < 2 || pp[0] != 0x04) return 0;
            size_t pk_len = pp[1];
            pp += 2; remaining -= 2;
            if (pk_len != 32 || remaining < 32) return 0;

            /* 用原始私钥重建 SM2_KEY（含公钥） */
            return sm2_key_set_private_key(key, pp);
        }

        return 0;
    }
    return 0;
}
#endif /* USE_GMSSL */

/* ============================================================
 * 密钥生成
 * ============================================================ */

SM2Util::KeyPair SM2Util::generateKeyPairBase64() {
#ifdef USE_GMSSL
    SM2_KEY key;
    memset(&key, 0, sizeof(key));

    if (sm2_key_generate(&key) != 1) {
        throw std::runtime_error("Failed to generate SM2 key pair");
    }

    // Use stack buffer (avoid CRT mismatch with GmSSL malloc)
    unsigned char pub_bytes[65];
    sm2_point_to_uncompressed_octets(&key.public_key, pub_bytes);

    KeyPair pair;
    pair.publicKey = Base64Util::encodeBase64Str(std::vector<unsigned char>(pub_bytes, pub_bytes + 65));
    pair.privateKey = Base64Util::encodeBase64Str(std::vector<unsigned char>(key.private_key, key.private_key + 32));
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
    SM2_KEY key;
    memset(&key, 0, sizeof(key));

    if (sm2_key_generate(&key) != 1) {
        throw std::runtime_error("Failed to generate SM2 key pair");
    }

    // Use stack buffer (avoid CRT mismatch with GmSSL malloc)
    unsigned char pub_bytes[65];
    sm2_point_to_uncompressed_octets(&key.public_key, pub_bytes);

    KeyPair pair;
    pair.publicKey = HexUtil::encodeHexStr(std::vector<unsigned char>(pub_bytes, pub_bytes + 65));
    pair.privateKey = HexUtil::encodeHexStr(std::vector<unsigned char>(key.private_key, key.private_key + 32));
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

SM2Util::KeyPair SM2Util::generateKeyPairRaw() {
#ifdef USE_GMSSL
    SM2_KEY key;
    memset(&key, 0, sizeof(key));

    if (sm2_key_generate(&key) != 1) {
        throw std::runtime_error("Failed to generate SM2 key pair");
    }

    // Convert public key to X.509 SubjectPublicKeyInfo DER
    uint8_t* pub_der = nullptr;
    size_t pub_der_len = 0;
    if (sm2_public_key_info_to_der(&key, &pub_der, &pub_der_len) != 1) {
        throw std::runtime_error("Failed to encode public key to X.509 DER");
    }

    // Convert private key to PKCS#8 PrivateKeyInfo DER
    uint8_t* priv_der = nullptr;
    size_t priv_der_len = 0;
    if (sm2_private_key_info_to_der(&key, &priv_der, &priv_der_len) != 1) {
        free(pub_der);
        throw std::runtime_error("Failed to encode private key to PKCS#8 DER");
    }

    KeyPair pair;
    pair.publicKey = HexUtil::encodeHexStr(std::vector<unsigned char>(pub_der, pub_der + pub_der_len));
    pair.privateKey = HexUtil::encodeHexStr(std::vector<unsigned char>(priv_der, priv_der + priv_der_len));

    free(pub_der);
    free(priv_der);
    return pair;
#else
    // Stub implementation: hand-craft DER-encoded key pair
    SM2Context ctx;
    // Public key: X.509 SubjectPublicKeyInfo DER
    //   30 59    SEQUENCE (89 bytes)
    //     30 13    SEQUENCE (19 bytes) — AlgorithmIdentifier
    //       06 07 2A811CCF5501822D   OID 1.2.156.10197.1.301 (SM2)
    //       06 08 2A811CCF5501822D   OID 1.2.156.10197.1.301 (curve param)
    //     03 42 00 BIT STRING (66 bytes) — 04||x||y uncompressed point
    std::vector<unsigned char> pub_der;
    pub_der.push_back(0x30); pub_der.push_back(0x59);
    pub_der.push_back(0x30); pub_der.push_back(0x13);
    pub_der.push_back(0x06); pub_der.push_back(0x07);
    pub_der.push_back(0x2A); pub_der.push_back(0x81); pub_der.push_back(0x1C);
    pub_der.push_back(0xCF); pub_der.push_back(0x55); pub_der.push_back(0x01);
    pub_der.push_back(0x82); pub_der.push_back(0x2D);
    pub_der.push_back(0x06); pub_der.push_back(0x08);
    pub_der.push_back(0x2A); pub_der.push_back(0x81); pub_der.push_back(0x1C);
    pub_der.push_back(0xCF); pub_der.push_back(0x55); pub_der.push_back(0x01);
    pub_der.push_back(0x82); pub_der.push_back(0x2D);
    pub_der.push_back(0x03); pub_der.push_back(0x42); pub_der.push_back(0x00);
    pub_der.insert(pub_der.end(), ctx.publicKey.begin(), ctx.publicKey.end());

    // Private key: PKCS#8 PrivateKeyInfo DER
    std::vector<unsigned char> priv_der;
    priv_der.push_back(0x30); priv_der.push_back(0x54);
    priv_der.push_back(0x02); priv_der.push_back(0x01); priv_der.push_back(0x00); // version
    // AlgorithmIdentifier
    priv_der.push_back(0x30); priv_der.push_back(0x13);
    priv_der.push_back(0x06); priv_der.push_back(0x07);
    priv_der.push_back(0x2A); priv_der.push_back(0x81); priv_der.push_back(0x1C);
    priv_der.push_back(0xCF); priv_der.push_back(0x55); priv_der.push_back(0x01);
    priv_der.push_back(0x82); priv_der.push_back(0x2D);
    priv_der.push_back(0x06); priv_der.push_back(0x08);
    priv_der.push_back(0x2A); priv_der.push_back(0x81); priv_der.push_back(0x1C);
    priv_der.push_back(0xCF); priv_der.push_back(0x55); priv_der.push_back(0x01);
    priv_der.push_back(0x82); priv_der.push_back(0x2D);
    // OCTET STRING wrapping ECPrivateKey SEQUENCE
    priv_der.push_back(0x04); priv_der.push_back(0x3A);
    priv_der.push_back(0x30); priv_der.push_back(0x38);
    priv_der.push_back(0x02); priv_der.push_back(0x01); priv_der.push_back(0x01); // version 1
    priv_der.push_back(0x04); priv_der.push_back(0x20); // private key OCTET STRING (32 bytes)
    priv_der.insert(priv_der.end(), ctx.privateKey.begin(), ctx.privateKey.end());
    // [1] EXPLICIT BIT STRING for public key (context-specific tag 1)
    priv_der.push_back(0xA1); priv_der.push_back(0x11);
    priv_der.push_back(0x03); priv_der.push_back(0x0F); priv_der.push_back(0x00);
    priv_der.insert(priv_der.end(), ctx.publicKey.begin(), ctx.publicKey.begin() + 15);

    KeyPair pair;
    pair.publicKey = HexUtil::encodeHexStr(pub_der);
    pair.privateKey = HexUtil::encodeHexStr(priv_der);
    return pair;
#endif
}

/* ============================================================
 * 加密
 * ============================================================ */

std::vector<unsigned char> SM2Util::encryptToBytes(const std::vector<unsigned char>& content, const std::vector<unsigned char>& publicKey) {
#ifdef USE_GMSSL
    SM2_KEY key;
    SM2_POINT point;

    if (!decodePublicKeyToPoint(publicKey.data(), publicKey.size(), &point)) {
        throw std::runtime_error("Failed to parse public key from bytes");
    }

    // Set only the public key part
    memset(&key, 0, sizeof(key));
    if (sm2_key_set_public_key(&key, &point) != 1) {
        throw std::runtime_error("Failed to set public key");
    }

    // Allocate output buffer (ciphertext is larger than plaintext)
    std::vector<uint8_t> ciphertext(content.size() + 1024);
    size_t ciphertext_len = ciphertext.size();

    if (sm2_encrypt(&key, content.data(), content.size(), ciphertext.data(), &ciphertext_len) != 1) {
        throw std::runtime_error("SM2 encryption failed");
    }

    ciphertext.resize(ciphertext_len);
    return ciphertext;
#else
    // Stub implementation
    std::vector<unsigned char> result;
    result.insert(result.end(), content.begin(), content.end());
    for (size_t i = 0; i < result.size(); ++i) {
        result[i] ^= (i % 256);
    }
    return result;
#endif
}

std::vector<unsigned char> SM2Util::encryptToBytes(const std::string& content, const std::string& publicKey, const std::string& charset) {
    auto contentBytes = StringUtil::stringToBytes(content, charset);
    auto publicKeyBytes = HexUtil::isHexString(publicKey) ? HexUtil::decodeHexStr(publicKey) : Base64Util::decodeBase64Str(publicKey);
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

/* ============================================================
 * 解密
 * 支持 GmSSL DER SEQUENCE 格式 (30开头) 和 Java RAW C1C3C2 格式 (04开头)
 * ============================================================ */

std::vector<unsigned char> SM2Util::decryptToBytes(const std::vector<unsigned char>& content, const std::vector<unsigned char>& privateKey) {
#ifdef USE_GMSSL
    SM2_KEY key;
    if (!decodePrivateKeyToKey(privateKey.data(), privateKey.size(), &key)) {
        throw std::runtime_error("Failed to parse private key from bytes");
    }

    // 检测密文格式: 0x04 = Java RAW C1C3C2, 0x30 = GmSSL DER SEQUENCE
    const uint8_t* ct_data = content.data();
    size_t ct_len = content.size();

    // For Java RAW C1C3C2 format (0x04 prefix), convert to DER first
    std::vector<uint8_t> der_ct;
    if (ct_len > 0 && ct_data[0] == 0x04) {
        der_ct = sm2_raw_c1c3c2_to_der(ct_data, ct_len);
        ct_data = der_ct.data();
        ct_len = der_ct.size();
    }
    // else: already DER SEQUENCE or other format, use directly

    std::vector<uint8_t> plaintext(ct_len);
    size_t plaintext_len = plaintext.size();

    if (sm2_decrypt(&key, ct_data, ct_len, plaintext.data(), &plaintext_len) != 1) {
        throw std::runtime_error("SM2 decryption failed");
    }

    plaintext.resize(plaintext_len);
    return plaintext;
#else
    // Stub implementation
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

    // Determine if privateKey is hex or base64 encoded and decode accordingly
    bool isPrivKeyHex = HexUtil::isHexString(privateKey);
    bool isPrivKeyBase64 = Base64Util::isBase64String(privateKey);

    std::vector<unsigned char> privateKeyBytes;
    if (isPrivKeyHex) {
        privateKeyBytes = HexUtil::decodeHexStr(privateKey);
    } else if (isPrivKeyBase64) {
        privateKeyBytes = Base64Util::decodeBase64Str(privateKey);
    } else {
        privateKeyBytes = StringUtil::stringToBytes(privateKey);
    }

    return decryptToBytes(contentBytes, privateKeyBytes);
}

std::string SM2Util::decryptToCharset(const std::string& content, const std::string& privateKey, const std::string& charset) {
    auto decryptedBytes = decryptToBytes(content, privateKey);
    return StringUtil::bytesToString(decryptedBytes, charset);
}

std::string SM2Util::decrypt(const std::string& content, const std::string& privateKey) {
    return decryptToCharset(content, privateKey, "UTF-8");
}

/* ============================================================
 * 签名 (使用 SM2_SIGN_CTX 上下文 API，与 Java SM3-with-ID 一致)
 * ============================================================ */

std::vector<unsigned char> SM2Util::sign(const std::vector<unsigned char>& content, const std::vector<unsigned char>& privateKey) {
#ifdef USE_GMSSL
    SM2_KEY key;
    if (!decodePrivateKeyToKey(privateKey.data(), privateKey.size(), &key)) {
        throw std::runtime_error("Failed to parse private key from bytes");
    }

    SM2_SIGN_CTX ctx;
    uint8_t sig_buf[SM2_SIGNATURE_DER_MAX_SIZE];
    size_t sig_len = sizeof(sig_buf);

    // Use SM3-with-ID signing context, USER_ID consistent with Java ("1234567812345678")
    if (sm2_sign_init(&ctx, &key, USER_ID.c_str(), USER_ID.length()) != 1) {
        throw std::runtime_error("SM2 sign init failed");
    }
    if (sm2_sign_update(&ctx, content.data(), content.size()) != 1) {
        throw std::runtime_error("SM2 sign update failed");
    }
    if (sm2_sign_finish(&ctx, sig_buf, &sig_len) != 1) {
        throw std::runtime_error("SM2 sign finish failed");
    }

    return std::vector<unsigned char>(sig_buf, sig_buf + sig_len);
#else
    // Stub implementation
    std::vector<unsigned char> signature(64);
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
        privateKeyBytes = StringUtil::stringToBytes(privateKey);
    }

    return sign(contentBytes, privateKeyBytes);
}

std::string SM2Util::signToHex(const std::string& content, const std::string& privateKey) {
    auto contentBytes = StringUtil::stringToBytes(content, "UTF-8");
    // Decode privateKey from hex or base64
    bool isHex = HexUtil::isHexString(privateKey);
    bool isBase64 = Base64Util::isBase64String(privateKey);
    std::vector<unsigned char> privateKeyBytes;
    if (isHex) {
        privateKeyBytes = HexUtil::decodeHexStr(privateKey);
    } else if (isBase64) {
        privateKeyBytes = Base64Util::decodeBase64Str(privateKey);
    } else {
        privateKeyBytes = StringUtil::stringToBytes(privateKey);
    }
    auto signature = sign(contentBytes, privateKeyBytes);
    return HexUtil::encodeHexStr(signature);
}

std::string SM2Util::signToBase64(const std::string& content, const std::string& privateKey) {
    auto contentBytes = StringUtil::stringToBytes(content, "UTF-8");
    // Decode privateKey from hex or base64
    bool isHex = HexUtil::isHexString(privateKey);
    bool isBase64 = Base64Util::isBase64String(privateKey);
    std::vector<unsigned char> privateKeyBytes;
    if (isHex) {
        privateKeyBytes = HexUtil::decodeHexStr(privateKey);
    } else if (isBase64) {
        privateKeyBytes = Base64Util::decodeBase64Str(privateKey);
    } else {
        privateKeyBytes = StringUtil::stringToBytes(privateKey);
    }
    auto signature = sign(contentBytes, privateKeyBytes);
    return Base64Util::encodeBase64Str(signature);
}

std::string SM2Util::sign(const std::string& content, const std::string& privateKey, bool toBase64) {
    if (toBase64) {
        return signToBase64(content, privateKey);
    } else {
        return signToHex(content, privateKey);
    }
}

/* ============================================================
 * 验签 (使用 SM2_SIGN_CTX 上下文 API)
 * ============================================================ */

bool SM2Util::verify(const std::vector<unsigned char>& content, const std::vector<unsigned char>& signature, const std::vector<unsigned char>& publicKey) {
#ifdef USE_GMSSL
    SM2_KEY key;
    SM2_POINT point;

    if (!decodePublicKeyToPoint(publicKey.data(), publicKey.size(), &point)) {
        throw std::runtime_error("Failed to parse public key from bytes");
    }

    memset(&key, 0, sizeof(key));
    if (sm2_key_set_public_key(&key, &point) != 1) {
        throw std::runtime_error("Failed to set public key for verification");
    }

    SM2_SIGN_CTX ctx;

    // Use SM3-with-ID verify context
    if (sm2_verify_init(&ctx, &key, USER_ID.c_str(), USER_ID.length()) != 1) {
        throw std::runtime_error("SM2 verify init failed");
    }
    if (sm2_verify_update(&ctx, content.data(), content.size()) != 1) {
        throw std::runtime_error("SM2 verify update failed");
    }
    // sm2_verify_finish: 1=success, <=0=failure
    int ret = sm2_verify_finish(&ctx, signature.data(), signature.size());
    return (ret == 1);
#else
    // Stub implementation
    if (signature.size() != 64) return false;

    std::vector<unsigned char> reconstructedPrivateKey(32);
    for (int i = 0; i < 32 && (i+1) < static_cast<int>(publicKey.size()); ++i) {
        reconstructedPrivateKey[i] = publicKey[i + 1] ^ ((i + 1) & 0xFF);
    }

    std::vector<unsigned char> expectedSignature(64);
    for (size_t i = 0; i < expectedSignature.size(); ++i) {
        if (i < content.size() && i < reconstructedPrivateKey.size()) {
            expectedSignature[i] = content[i] ^ reconstructedPrivateKey[i] ^ (static_cast<unsigned char>(i & 0xFF));
        } else if (i < content.size()) {
            expectedSignature[i] = content[i] ^ (static_cast<unsigned char>((i * 17) & 0xFF));
        } else if (i < reconstructedPrivateKey.size()) {
            expectedSignature[i] = reconstructedPrivateKey[i] ^ (static_cast<unsigned char>((i * 23) & 0xFF));
        } else {
            expectedSignature[i] = (static_cast<unsigned char>((i * 37) & 0xFF));
        }
    }

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
        signatureBytes = StringUtil::stringToBytes(signature);
    }

    return verify(contentBytes, signatureBytes, publicKeyBytes);
}

/* ============================================================
 * 组合操作：加密+签名 / 验签+解密
 * ============================================================ */

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

/* ============================================================
 * PEM Export / Import
 * ============================================================ */

static std::string toPem(const std::string& type, const std::vector<unsigned char>& der) {
    std::string b64 = Base64Util::encodeBase64Str(der);
    std::string result = "-----BEGIN " + type + "-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) {
        result += b64.substr(i, 64) + "\n";
    }
    result += "-----END " + type + "-----\n";
    return result;
}

static std::vector<unsigned char> fromPem(const std::string& pem, const std::string& type) {
    std::string begin = "-----BEGIN " + type + "-----";
    std::string end   = "-----END " + type + "-----";
    size_t start = pem.find(begin);
    size_t finish = pem.find(end);
    if (start == std::string::npos || finish == std::string::npos) {
        throw std::runtime_error("Invalid PEM: missing " + type + " boundaries");
    }
    std::string b64 = pem.substr(start + begin.size(), finish - (start + begin.size()));
    // Remove whitespace
    b64.erase(std::remove_if(b64.begin(), b64.end(), ::isspace), b64.end());
    return Base64Util::decodeBase64Str(b64);
}

std::string SM2Util::exportKeyPem(const std::string& derHex, const std::string& type) {
    auto der = HexUtil::decodeHexStr(derHex);
    return toPem(type, der);
}

std::string SM2Util::importKeyPem(const std::string& pem, const std::string& type) {
    auto der = fromPem(pem, type);
    return HexUtil::encodeHexStr(der);
}
