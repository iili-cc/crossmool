// crossmool-cpp 完整单元测试
// 覆盖 SM2 / SM3 / SM4 / Util 所有公开 API
#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include <stdexcept>

#include "SM2Util.h"
#include "SM3Util.h"
#include "SM4Util.h"
#include "HexUtil.h"
#include "Base64Util.h"
#include "StringUtil.h"

static int total = 0, passed = 0;

#define TEST(name, expr) do { \
    total++; \
    std::cout << "  [" << (expr ? "PASS" : "FAIL") << "] " << name << std::endl; \
    if (expr) passed++; \
} while(0)

void test_sm2_keygen() {
    std::cout << "\n--- SM2 Key Generation ---\n";
    auto kp_b64 = SM2Util::generateKeyPairBase64();
    TEST("generateKeyPairBase64 pub", !kp_b64.publicKey.empty());
    TEST("generateKeyPairBase64 priv", !kp_b64.privateKey.empty());
    TEST("Base64 pub decodable", Base64Util::isBase64String(kp_b64.publicKey));

    auto kp_hex = SM2Util::generateKeyPairHex();
    TEST("generateKeyPairHex pub", !kp_hex.publicKey.empty());
    TEST("generateKeyPairHex priv", !kp_hex.privateKey.empty());
    TEST("Hex pub len 130", kp_hex.publicKey.length() == 130);
    TEST("Hex priv len 64", kp_hex.privateKey.length() == 64);
    TEST("Pub starts with 04", kp_hex.publicKey.substr(0, 2) == "04");
    TEST("Hex pub is valid hex", HexUtil::isHexString(kp_hex.publicKey));

    auto kp_raw = SM2Util::generateKeyPairRaw();
    TEST("generateKeyPairRaw pub", !kp_raw.publicKey.empty());
    TEST("generateKeyPairRaw priv", !kp_raw.privateKey.empty());
    TEST("Raw pub is valid hex", HexUtil::isHexString(kp_raw.publicKey));
    TEST("Raw priv is valid hex", HexUtil::isHexString(kp_raw.privateKey));
}

void test_sm2_encrypt_decrypt() {
    std::cout << "\n--- SM2 Encrypt/Decrypt ---\n";
    auto kp = SM2Util::generateKeyPairHex();
    std::string plain = "Hello, SM2 Encryption!";

    // encrypt(data, key, toBase64) / decrypt
    std::string ct_hex = SM2Util::encrypt(plain, kp.publicKey, false);
    TEST("encrypt hex not empty", !ct_hex.empty());
    std::string dec = SM2Util::decrypt(ct_hex, kp.privateKey);
    TEST("decrypt match", dec == plain);

    // encryptToHex
    std::string ct_hex2 = SM2Util::encryptToHex(plain, kp.publicKey);
    TEST("encryptToHex not empty", !ct_hex2.empty());

    // encryptToBase64
    std::string ct_b64 = SM2Util::encryptToBase64(plain, kp.publicKey);
    TEST("encryptToBase64 not empty", !ct_b64.empty());

    // Base64 encrypt + decrypt
    std::string ct_b64_2 = SM2Util::encrypt(plain, kp.publicKey, true);
    std::string dec2 = SM2Util::decrypt(ct_b64_2, kp.privateKey);
    TEST("Base64 roundtrip", dec2 == plain);

    // encryptToBytes
    auto ct_bytes = SM2Util::encryptToBytes(plain, kp.publicKey, "UTF-8");
    TEST("encryptToBytes not empty", !ct_bytes.empty());

    // decryptToBytes (string input)
    auto dec_bytes = SM2Util::decryptToBytes(ct_hex, kp.privateKey);
    TEST("decryptToBytes match", std::string(dec_bytes.begin(), dec_bytes.end()) == plain);
}

void test_sm2_sign_verify() {
    std::cout << "\n--- SM2 Sign/Verify ---\n";
    auto kp = SM2Util::generateKeyPairHex();
    std::string msg = "Message to sign";

    // sign(msg, key, toBase64=false) -> hex
    std::string sig_hex = SM2Util::sign(msg, kp.privateKey, false);
    TEST("sign hex not empty", !sig_hex.empty());
    TEST("sign hex is hex", HexUtil::isHexString(sig_hex));

    // verify correct
    bool ok = SM2Util::verify(msg, kp.publicKey, sig_hex);
    TEST("verify pass", ok);

    // verify wrong msg
    ok = SM2Util::verify("Wrong", kp.publicKey, sig_hex);
    TEST("verify fail wrong msg", !ok);

    // signToHex
    std::string sig_h2 = SM2Util::signToHex(msg, kp.privateKey);
    TEST("signToHex not empty", !sig_h2.empty());

    // signToBase64
    std::string sig_b64 = SM2Util::signToBase64(msg, kp.privateKey);
    TEST("signToBase64 not empty", !sig_b64.empty());
    TEST("signToBase64 is base64", Base64Util::isBase64String(sig_b64));
}

void test_sm2_encrypt_sign_combo() {
    std::cout << "\n--- SM2 Encrypt+Sign / Verify+Decrypt ---\n";
    auto enc_kp = SM2Util::generateKeyPairHex();
    auto sign_kp = SM2Util::generateKeyPairHex();
    std::string content = "Combo test content";

    auto pair = SM2Util::encryptSign(content, enc_kp.publicKey, sign_kp.privateKey, false);
    TEST("encryptSign ciphertext", !pair.ciphertext.empty());
    TEST("encryptSign signature", !pair.signature.empty());

    std::string result = SM2Util::verifyDecrypt(pair.ciphertext, pair.signature,
                                                  sign_kp.publicKey, enc_kp.privateKey);
    TEST("verifyDecrypt match", result == content);
}

void test_sm3_digest() {
    std::cout << "\n--- SM3 Digest ---\n";
    std::string input = "hello sm3";

    // digestToStr(string, charset, toBase64)
    std::string d = SM3Util::digestToStr(input, "UTF-8", false);
    TEST("digest hex len 64", d.length() == 64);
    TEST("digest hex is hex", HexUtil::isHexString(d));

    // digestToStr(string, charset, toBase64=true)
    std::string d3 = SM3Util::digestToStr(input, "UTF-8", true);
    TEST("digestToStr base64", Base64Util::isBase64String(d3));

    // hex deterministic
    std::string d4 = SM3Util::digestToStr(input, "UTF-8", false);
    TEST("SM3 deterministic", d == d4);

    // digest(vector) raw
    std::vector<unsigned char> v(input.begin(), input.end());
    auto raw = SM3Util::digest(v);
    TEST("digest raw len 32", raw.size() == 32);

    // digestToHex(vector)
    std::string hex = SM3Util::digestToHex(v);
    TEST("digestToHex len 64", hex.length() == 64);
}

void test_sm3_hmac() {
    std::cout << "\n--- SM3 HMAC ---\n";
    std::string key = SM3Util::generateHmacKeyToStr(32, false);
    std::string data = "test data";

    // hmacToStr(string, string)
    std::string hm = SM3Util::hmacToStr(data, key, false);
    TEST("hmacToStr hex len 64", hm.length() == 64);

    // hmacToStr(string, string, base64)
    std::string hm_b64 = SM3Util::hmacToStr(data, key, true);
    TEST("hmacToStr base64", Base64Util::isBase64String(hm_b64));

    // hmacVerify
    TEST("hmacVerify pass", SM3Util::hmacVerify(data, key, hm));
    // Test with invalid HMAC - should fail verification
    std::string wrongKey = SM3Util::generateHmacKeyToStr(32, false);
    std::string wrongHmac = SM3Util::hmacToStr(data, wrongKey, false);
    TEST("hmacVerify fail wrong key", !SM3Util::hmacVerify(data, key, wrongHmac));
    TEST("hmacVerify fail wrong data", !SM3Util::hmacVerify("wrong_data", key, hm));

    // hmac(vector, vector)
    std::vector<unsigned char> vKey = HexUtil::decodeHexStr(key);
    std::vector<unsigned char> vData(data.begin(), data.end());
    auto raw_hmac = SM3Util::hmac(vData, vKey);
    TEST("hmac raw len 32", raw_hmac.size() == 32);

    // generateHmacKey
    auto gk = SM3Util::generateHmacKey(32);
    TEST("generateHmacKey len 32", gk.size() == 32);

    auto gkStr = SM3Util::generateHmacKeyToStr(32, false);
    TEST("generateHmacKeyToStr hex len 64", gkStr.length() == 64);

    auto gkB64 = SM3Util::generateHmacKeyToStr(32, true);
    TEST("generateHmacKeyToStr base64", Base64Util::isBase64String(gkB64));
}

void test_sm4_gcm() {
    std::cout << "\n--- SM4 GCM ---\n";

    std::string keyHex = SM4Util::generateKeyAsHex();
    auto key = SM4Util::parseHexKey(keyHex);
    TEST("generateKeyAsHex len 32", keyHex.length() == 32);
    TEST("parseHexKey len 16", key.size() == 16);

    std::string plain = "Hello, SM4 GCM!";
    std::vector<unsigned char> vPlain(plain.begin(), plain.end());

    // encryptGcm / decryptGcm (hex default)
    std::string ct_hex = SM4Util::encryptGcm(key, vPlain, false);
    TEST("encryptGcm hex not empty", !ct_hex.empty());
    auto dec = SM4Util::decryptGcm(key, ct_hex);
    TEST("decryptGcm hex len match", dec.size() == vPlain.size());
    TEST("decryptGcm hex data", std::string(dec.begin(), dec.end()) == plain);

    // encryptGcm / decryptGcm (base64)
    std::string ct_b64 = SM4Util::encryptGcm(key, vPlain, true);
    auto dec_b64 = SM4Util::decryptGcm(key, ct_b64);
    TEST("decryptGcm b64 data", std::string(dec_b64.begin(), dec_b64.end()) == plain);

    // encryptGcmString / decryptGcmToString
    std::string ct_str = SM4Util::encryptGcmString(key, plain);
    TEST("encryptGcmString not empty", !ct_str.empty());
    std::string dec_str = SM4Util::decryptGcmToString(key, ct_str);
    TEST("decryptGcmToString match", dec_str == plain);

    // random IV
    std::string ct1 = SM4Util::encryptGcm(key, vPlain, false);
    std::string ct2 = SM4Util::encryptGcm(key, vPlain, false);
    TEST("random IV: ct differs", ct1 != ct2);

    // generateKey()
    auto keyVec = SM4Util::generateKey();
    TEST("generateKey len 16", keyVec.size() == 16);

    // empty plaintext
    std::vector<unsigned char> empty;
    std::string ct_empty = SM4Util::encryptGcm(key, empty, false);
    auto dec_empty = SM4Util::decryptGcm(key, ct_empty);
    TEST("empty plain roundtrip", dec_empty.empty());
}

void test_utils() {
    std::cout << "\n--- Utils ---\n";
    std::string src = "Hello World";
    std::vector<unsigned char> v(src.begin(), src.end());

    // Hex
    std::string hex = HexUtil::encodeHexStr(v);
    auto dec_h = HexUtil::decodeHexStr(hex);
    TEST("Hex roundtrip", std::string(dec_h.begin(), dec_h.end()) == src);
    TEST("isHexString", HexUtil::isHexString("deadbeef"));
    TEST("isHexString fail", !HexUtil::isHexString("xyz"));

    // Base64
    std::string b64 = Base64Util::encodeBase64Str(v);
    auto dec_b = Base64Util::decodeBase64Str(b64);
    TEST("Base64 roundtrip", std::string(dec_b.begin(), dec_b.end()) == src);
    TEST("isBase64String", Base64Util::isBase64String("SGVsbG8="));
    TEST("isBase64String fail", !Base64Util::isBase64String("!@#"));

    // String charset
    auto sb = StringUtil::stringToBytes("Test", "UTF-8");
    TEST("stringToBytes len", sb.size() == 4);
    std::string bs = StringUtil::bytesToString(sb, "UTF-8");
    TEST("bytesToString", bs == "Test");
    TEST("StringUtil isHex", StringUtil::isHexString("abcd"));
    TEST("StringUtil isBase64", StringUtil::isBase64String("SGVsbG8="));
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  crossmool-cpp Unit Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_utils();
        test_sm2_keygen();
        test_sm2_encrypt_decrypt();
        test_sm2_sign_verify();
        test_sm2_encrypt_sign_combo();
        test_sm3_digest();
        test_sm3_hmac();
        test_sm4_gcm();

        std::cout << "\n========================================" << std::endl;
        std::cout << "  Results: " << passed << " / " << total << " passed";
        if (passed == total) {
            std::cout << "  [ALL PASS]" << std::endl;
        } else {
            std::cout << "  [" << (total - passed) << " FAILED]" << std::endl;
        }
        std::cout << "========================================" << std::endl;
        return (passed == total) ? 0 : 1;

    } catch (const std::exception& e) {
        std::cerr << "EXCEPTION: " << e.what() << std::endl;
        return 1;
    }
}
