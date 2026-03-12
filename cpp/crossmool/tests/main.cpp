#include <iostream>
#include <string>
#include <vector>
#include <cassert>

#include "SM2Util.h"
#include "SM3Util.h"
#include "SM4Util.h"
#include "HexUtil.h"
#include "Base64Util.h"
#include "StringUtil.h"

void testSM2() {
    std::cout << "Testing SM2 functionality...\n";

    // Test key generation
    auto keyPairBase64 = SM2Util::generateKeyPairBase64();
    std::cout << "Generated Base64 key pair\n";
    std::cout << "Public key (Base64): " << keyPairBase64.publicKey.substr(0, 30) << "...\n";
    std::cout << "Private key (Base64): " << keyPairBase64.privateKey.substr(0, 30) << "...\n";

    auto keyPairHex = SM2Util::generateKeyPairHex();
    std::cout << "Generated Hex key pair\n";
    std::cout << "Public key (Hex): " << keyPairHex.publicKey.substr(0, 30) << "...\n";
    std::cout << "Private key (Hex): " << keyPairHex.privateKey.substr(0, 30) << "...\n";

    // Test encryption/decryption
    std::string plaintext = "Hello, SM2!";
    std::string encryptedHex = SM2Util::encrypt(plaintext, keyPairHex.publicKey, false);
    std::string decrypted = SM2Util::decrypt(encryptedHex, keyPairHex.privateKey);
    std::cout << "Encrypted (Hex): " << encryptedHex.substr(0, 30) << "...\n";
    std::cout << "Decrypted: " << decrypted << "\n";
    assert(plaintext == decrypted);
    std::cout << "✓ Encryption/Decryption test passed\n";

    // Test encryption/decryption with Base64
    std::string encryptedBase64 = SM2Util::encrypt(plaintext, keyPairBase64.publicKey, true);
    std::string decryptedFromBase64 = SM2Util::decrypt(encryptedBase64, keyPairBase64.privateKey);
    std::cout << "Encrypted (Base64): " << encryptedBase64.substr(0, 30) << "...\n";
    std::cout << "Decrypted from Base64: " << decryptedFromBase64 << "\n";
    assert(plaintext == decryptedFromBase64);
    std::cout << "✓ Base64 Encryption/Decryption test passed\n";

    // Test signing/verification
    std::string signatureHex = SM2Util::sign(plaintext, keyPairHex.privateKey, false);
    bool verified = SM2Util::verify(plaintext, keyPairHex.publicKey, signatureHex);
    std::cout << "Signature (Hex): " << signatureHex.substr(0, 30) << "...\n";
    std::cout << "Verification result: " << (verified ? "PASS" : "FAIL") << "\n";
    assert(verified);
    std::cout << "✓ Signing/Verification test passed\n";

    // Test signing/verification with Base64
    std::string signatureBase64 = SM2Util::sign(plaintext, keyPairBase64.privateKey, true);
    bool verifiedBase64 = SM2Util::verify(plaintext, keyPairBase64.publicKey, signatureBase64);
    std::cout << "Signature (Base64): " << signatureBase64.substr(0, 30) << "...\n";
    std::cout << "Base64 Verification result: " << (verifiedBase64 ? "PASS" : "FAIL") << "\n";
    assert(verifiedBase64);
    std::cout << "✓ Base64 Signing/Verification test passed\n";

    std::cout << "✓ All SM2 tests passed!\n\n";
}

void testSM3() {
    std::cout << "Testing SM3 functionality...\n";

    std::string input = "Hello, SM3!";
    std::string hashHex = SM3Util::digestToStr(input, "UTF-8", false);
    std::string hashBase64 = SM3Util::digestToStr(input, "UTF-8", true);

    std::cout << "Input: " << input << "\n";
    std::cout << "Hash (Hex): " << hashHex << "\n";
    std::cout << "Hash (Base64): " << hashBase64 << "\n";

    // The hex hash should be 64 characters (32 bytes * 2)
    assert(hashHex.length() == 64);
    std::cout << "✓ SM3 hash length check passed\n";

    // Test HMAC-SM3
    auto hmacKey = SM3Util::generateHmacKey(32);
    std::string hmacKeyHex = HexUtil::encodeHexStr(hmacKey);
    std::string hmacResult = SM3Util::hmacToStr(hmacKeyHex, input, false);
    std::string hmacResultBase64 = SM3Util::hmacToStr(hmacKeyHex, input, true);

    std::cout << "HMAC Key (Hex): " << hmacKeyHex.substr(0, 30) << "...\n";
    std::cout << "HMAC Result (Hex): " << hmacResult << "\n";
    std::cout << "HMAC Result (Base64): " << hmacResultBase64 << "\n";

    // Verify HMAC
    bool hmacVerified = SM3Util::hmacVerify(hmacKeyHex, input, hmacResult);
    std::cout << "HMAC Verification: " << (hmacVerified ? "PASS" : "FAIL") << "\n";
    assert(hmacVerified);
    std::cout << "✓ HMAC-SM3 test passed\n";

    std::cout << "✓ All SM3 tests passed!\n\n";
}

void testSM4() {
    std::cout << "Testing SM4 functionality...\n";

    // Generate a key
    std::string keyHex = SM4Util::generateKeyAsHex();
    auto key = SM4Util::parseHexKey(keyHex);
    std::string plaintext = "Hello, SM4! This is a test.";

    std::cout << "Generated Key (Hex): " << keyHex << "\n";
    std::cout << "Plaintext: " << plaintext << "\n";

    // Test native encryption/decryption
    auto plaintextBytes = StringUtil::stringToBytes(plaintext, "UTF-8");
    std::string encrypted = SM4Util::encryptEcbNative(key, plaintextBytes);
    std::string decrypted = SM4Util::decryptEcbNative(key, encrypted);

    std::cout << "Encrypted (Hex): " << encrypted.substr(0, 30) << "...\n";
    std::cout << "Decrypted: " << decrypted << "\n";
    assert(plaintext == decrypted);
    std::cout << "✓ SM4 Native encryption/decryption test passed\n";

    // Test JCA-style encryption/decryption
    std::string encryptedJca = SM4Util::encryptEcbJca(key, plaintext);
    std::string decryptedJca = SM4Util::decryptEcbJca(key, encryptedJca);

    std::cout << "JCA Encrypted (Hex): " << encryptedJca.substr(0, 30) << "...\n";
    std::cout << "JCA Decrypted: " << decryptedJca << "\n";
    assert(plaintext == decryptedJca);
    std::cout << "✓ SM4 JCA-style encryption/decryption test passed\n";

    std::cout << "✓ All SM4 tests passed!\n\n";
}

void testUtils() {
    std::cout << "Testing utility functions...\n";

    // Test Base64 encoding/decoding
    std::string testStr = "Hello, World!";
    std::vector<unsigned char> testBytes(testStr.begin(), testStr.end());
    std::string encoded = Base64Util::encodeBase64Str(testBytes);
    auto decoded = Base64Util::decodeBase64Str(encoded);

    std::cout << "Original: " << testStr << "\n";
    std::cout << "Base64 Encoded: " << encoded << "\n";
    std::cout << "Decoded back: " << std::string(decoded.begin(), decoded.end()) << "\n";
    assert(testStr == std::string(decoded.begin(), decoded.end()));
    std::cout << "✓ Base64 encoding/decoding test passed\n";

    // Test Hex encoding/decoding
    std::string hexEncoded = HexUtil::encodeHexStr(testBytes);
    auto hexDecoded = HexUtil::decodeHexStr(hexEncoded);

    std::cout << "Hex Encoded: " << hexEncoded << "\n";
    std::cout << "Hex Decoded back: " << std::string(hexDecoded.begin(), hexDecoded.end()) << "\n";
    assert(testStr == std::string(hexDecoded.begin(), hexDecoded.end()));
    std::cout << "✓ Hex encoding/decoding test passed\n";

    // Test charset conversion
    std::string utf8Test = "你好，世界！";  // Chinese characters
    auto utf8Bytes = StringUtil::stringToBytes(utf8Test, "UTF-8");
    std::string utf8Back = StringUtil::bytesToString(utf8Bytes, "UTF-8");

    std::cout << "UTF-8 Original: " << utf8Test << "\n";
    std::cout << "UTF-8 Back: " << utf8Back << "\n";
    assert(utf8Test == utf8Back);
    std::cout << "✓ UTF-8 conversion test passed\n";

    std::cout << "✓ All utility tests passed!\n\n";
}

int main() {
    std::cout << "Running Crossmool C++ Tests\n";
    std::cout << "==========================\n\n";

    try {
        testUtils();
        testSM2();
        testSM3();
        testSM4();

        std::cout << "🎉 All tests passed successfully!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}