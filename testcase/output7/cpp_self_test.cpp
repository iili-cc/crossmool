#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include "SM2Util.h"
#include "SM3Util.h"
#include "SM4Util.h"
#include "HexUtil.h"
#include "Base64Util.h"

#define MSG "Hello, \xe8\xbf\x99\xe6\x98\xaf\xe8\xb7\xa8\xe8\xaf\xad\xe8\xa8\x80\xe5\x9b\xbd\xe5\xaf\x86\xe4\xba\x92\xe9\x80\x9a\xe6\x80\xa7\xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae"
#define SM4_KEY_HEX "0123456789abcdeffedcba9876543210"
#define HMAC_KEY_HEX "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
#define EXP_SM3 "0880efb46176002c6cd1d94bcc3d9d9161488e099317d34a4d6b28b7becef36b"
#define EXP_SM3_HMAC "3e0c629ac18e2ad27415a549707565b0063872d65384e88ee2d1f88735b280f6"
#define ENC_PUB_HEX "3059301306072a8648ce3d020106082a811ccf5501822d03420004c7e07058fb62e2da4c053da10c37af4547650d9092f260ea4304b18dc0845856c539b313de0b676c208a99e21c78dbee410e3805adbb42b42fed8b57446f7356"
/* Use raw 32-byte keys for C++ since GmSSL PKCS#8 parsing may have issues */
#define ENC_PRIV_RAW "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03"
#define SIG_PUB_HEX "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226"
#define SIG_PRIV_RAW "f819b994f4c99bf5bbd47a94b1c23cfee6d67fb21c4ec25c162a2f9a9424c7e3"

static void json_out(const std::string& key, const std::string& val, int& first) {
    if (first) first = 0; else std::cout << ",";
    std::cout << "\"" << key << "\":\"" << val << "\"";
}

int main() {
    int first = 1;
    std::cout << "{\"lang\":\"cpp\"";
    std::cerr << "[CPP] Starting self-test..." << std::endl;

    try {
        std::string msg(MSG);
        std::vector<unsigned char> msgBytes(msg.begin(), msg.end());
        std::string enc = SM2Util::encryptToHex(msg, ENC_PUB_HEX);
        json_out("sm2_enc", enc, first);
        std::vector<unsigned char> pubBytes = HexUtil::decodeHexStr(ENC_PUB_HEX);
        std::string dec = SM2Util::decrypt(enc, ENC_PRIV_RAW);
        json_out("sm2_enc_dec", (dec == msg) ? "PASS" : "FAIL", first);
        std::cerr << "[CPP] SM2 Enc/Dec: " << ((dec == msg) ? "PASS" : "FAIL") << std::endl;
    } catch (const std::exception& e) {
        json_out("sm2_enc_dec", std::string("FAIL: ") + e.what(), first);
        std::cerr << "[CPP] SM2 Enc/Dec FAIL: " << e.what() << std::endl;
    }

    try {
        std::string msg(MSG);
        std::vector<unsigned char> msgBytes(msg.begin(), msg.end());
        std::string sig = SM2Util::signToHex(msg, SIG_PRIV_RAW);
        json_out("sm2_sig", sig, first);
        bool ok = SM2Util::verify(msg, SIG_PUB_HEX, sig);
        json_out("sm2_sig_ver", ok ? "PASS" : "FAIL", first);
        std::cerr << "[CPP] SM2 Sign/Verify: " << (ok ? "PASS" : "FAIL") << std::endl;
    } catch (const std::exception& e) {
        json_out("sm2_sig_ver", std::string("FAIL: ") + e.what(), first);
        std::cerr << "[CPP] SM2 Sign/Verify FAIL: " << e.what() << std::endl;
    }

    try {
        std::string msg(MSG);
        auto pair = SM2Util::encryptSign(msg, ENC_PUB_HEX, SIG_PRIV_RAW, false);
        std::string dec2 = SM2Util::verifyDecrypt(pair.ciphertext, pair.signature, SIG_PUB_HEX, ENC_PRIV_RAW);
        json_out("sm2_enc_sig_ver_dec", (dec2 == msg) ? "PASS" : "FAIL", first);
        std::cerr << "[CPP] SM2 ES/VD: " << ((dec2 == msg) ? "PASS" : "FAIL") << std::endl;
    } catch (const std::exception& e) {
        json_out("sm2_enc_sig_ver_dec", std::string("FAIL: ") + e.what(), first);
        std::cerr << "[CPP] SM2 ES/VD FAIL: " << e.what() << std::endl;
    }

    try {
        std::string msg(MSG);
        std::string h = SM3Util::digestToStr(msg, "UTF-8", false);
        json_out("sm3_hash", h, first);
        json_out("sm3", (h == EXP_SM3) ? "PASS" : "FAIL", first);
        std::cerr << "[CPP] SM3: " << ((h == EXP_SM3) ? "PASS" : "FAIL") << std::endl;
    } catch (const std::exception& e) {
        json_out("sm3", std::string("FAIL: ") + e.what(), first);
    }

    try {
        std::vector<unsigned char> hmacKey = HexUtil::decodeHexStr(HMAC_KEY_HEX);
        std::string msg(MSG);
        std::vector<unsigned char> msgBytes(msg.begin(), msg.end());
        std::string hm = SM3Util::hmacToStr(hmacKey, msgBytes, false);
        json_out("sm3_hmac_hash", hm, first);
        json_out("sm3_hmac", (hm == EXP_SM3_HMAC) ? "PASS" : "FAIL", first);
        std::cerr << "[CPP] SM3-HMAC: " << ((hm == EXP_SM3_HMAC) ? "PASS" : "FAIL") << std::endl;
    } catch (const std::exception& e) {
        json_out("sm3_hmac", std::string("FAIL: ") + e.what(), first);
    }

    try {
        std::vector<unsigned char> sm4Key = HexUtil::decodeHexStr(SM4_KEY_HEX);
        std::string msg(MSG);
        std::vector<unsigned char> msgBytes(msg.begin(), msg.end());
        std::string sc = SM4Util::encryptGcm(sm4Key, msgBytes, false);
        json_out("sm4_enc", sc, first);
        std::vector<unsigned char> sd = SM4Util::decryptGcm(sm4Key, sc);
        std::string sdStr(sd.begin(), sd.end());
        json_out("sm4_enc_dec", (sdStr == msg) ? "PASS" : "FAIL", first);
        std::cerr << "[CPP] SM4 GCM: " << ((sdStr == msg) ? "PASS" : "FAIL") << std::endl;
    } catch (const std::exception& e) {
        json_out("sm4_enc_dec", std::string("FAIL: ") + e.what(), first);
    }

    std::cout << "}" << std::endl;
    return 0;
}
