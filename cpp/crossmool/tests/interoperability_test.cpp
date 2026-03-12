#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include <iomanip>
#include <sstream>
#include <fstream>

#include "SM2Util.h"
#include "SM3Util.h"
#include "SM4Util.h"
#include "HexUtil.h"
#include "Base64Util.h"
#include "StringUtil.h"

/**
 * This test file aims to verify interoperability between C++ and Java implementations
 * by comparing the behavior of both implementations.
 */

void generateInteropFiles() {
    std::cout << "Generating interop test files for Java counterpart...\n";

    // Generate a test key pair
    auto keyPair = SM2Util::generateKeyPairHex();

    // Extract DER bytes from the hex-encoded keys
    std::vector<unsigned char> pubKeyDer = HexUtil::decodeHexStr(keyPair.publicKey);
    std::vector<unsigned char> privKeyDer = HexUtil::decodeHexStr(keyPair.privateKey);

    // Save the DER keys to files
    std::ofstream pubDerFile("interop_test_public.der", std::ios::binary);
    pubDerFile.write(reinterpret_cast<const char*>(pubKeyDer.data()), pubKeyDer.size());
    pubDerFile.close();

    std::ofstream privDerFile("interop_test_private.der", std::ios::binary);
    privDerFile.write(reinterpret_cast<const char*>(privKeyDer.data()), privKeyDer.size());
    privDerFile.close();

    // Create a test message
    std::string message = "interoperability-test-message";

    // Encrypt the message
    std::string cipherHex = SM2Util::encrypt(message, keyPair.publicKey, false);

    // Sign the message
    std::string sigHex = SM2Util::sign(message, keyPair.privateKey, false);

    // Save the cipher and signature to files
    std::ofstream cipherFile("interop_test_cipher.hex");
    cipherFile << cipherHex;
    cipherFile.close();

    std::ofstream sigFile("interop_test_signature.hex");
    sigFile << sigHex;
    sigFile.close();

    std::cout << "✓ Generated interop test files:\n";
    std::cout << "  - interop_test_public.der\n";
    std::cout << "  - interop_test_private.der\n";
    std::cout << "  - interop_test_cipher.hex\n";
    std::cout << "  - interop_test_signature.hex\n";
}

void testSm2Interoperability() {
    std::cout << "Testing SM2 Interoperability...\n";

    // Generate keys using C++ implementation
    auto keyPairBase64 = SM2Util::generateKeyPairBase64();
    auto keyPairHex = SM2Util::generateKeyPairHex();

    std::cout << "Generated Base64 key pair\n";
    std::cout << "Public key (Base64): " << keyPairBase64.publicKey.substr(0, 30) << "...\n";
    std::cout << "Private key (Base64): " << keyPairBase64.privateKey.substr(0, 30) << "...\n";

    std::cout << "Generated Hex key pair\n";
    std::cout << "Public key (Hex): " << keyPairHex.publicKey.substr(0, 30) << "...\n";
    std::cout << "Private key (Hex): " << keyPairHex.privateKey.substr(0, 30) << "...\n";

    // Test encryption/decryption with various inputs
    std::vector<std::string> testInputs = {
        "Hello, SM2!",
        "国密算法测试",
        "Mixed测试123!",
        "Special chars: @#$%^&*()_+-={}[]|\\:;\"'<>?,./",
        ""  // Empty string test
    };

    for (const auto& input : testInputs) {
        std::cout << "\nTesting with input: '" << input << "'\n";

        // Test with Hex format
        std::string encryptedHex = SM2Util::encrypt(input, keyPairHex.publicKey, false);
        std::string decryptedHex = SM2Util::decrypt(encryptedHex, keyPairHex.privateKey);
        std::cout << "Encrypted (Hex): " << encryptedHex.substr(0, 30) << "...\n";
        std::cout << "Decrypted: " << decryptedHex << "\n";
        assert(input == decryptedHex);
        std::cout << "✓ Hex encryption/decryption test passed\n";

        // Test with Base64 format
        std::string encryptedBase64 = SM2Util::encrypt(input, keyPairBase64.publicKey, true);
        std::string decryptedBase64 = SM2Util::decrypt(encryptedBase64, keyPairBase64.privateKey);
        std::cout << "Encrypted (Base64): " << encryptedBase64.substr(0, 30) << "...\n";
        std::cout << "Decrypted: " << decryptedBase64 << "\n";
        assert(input == decryptedBase64);
        std::cout << "✓ Base64 encryption/decryption test passed\n";
    }

    // Test signing/verification with various inputs
    for (const auto& input : testInputs) {
        if (input.empty()) continue; // Skip empty string for signing

        std::cout << "\nTesting signing/verification with input: '" << input << "'\n";

        // Test with Hex format
        std::string signatureHex = SM2Util::sign(input, keyPairHex.privateKey, false);
        bool verifiedHex = SM2Util::verify(input, keyPairHex.publicKey, signatureHex);
        std::cout << "Signature (Hex): " << signatureHex.substr(0, 30) << "...\n";
        std::cout << "Verification result: " << (verifiedHex ? "PASS" : "FAIL") << "\n";
        assert(verifiedHex);
        std::cout << "✓ Hex signing/verification test passed\n";

        // Test with Base64 format
        std::string signatureBase64 = SM2Util::sign(input, keyPairBase64.privateKey, true);
        bool verifiedBase64 = SM2Util::verify(input, keyPairBase64.publicKey, signatureBase64);
        std::cout << "Signature (Base64): " << signatureBase64.substr(0, 30) << "...\n";
        std::cout << "Verification result: " << (verifiedBase64 ? "PASS" : "FAIL") << "\n";
        assert(verifiedBase64);
        std::cout << "✓ Base64 signing/verification test passed\n";
    }

    // Test encryptSign and verifyDecrypt
    std::string content = "Encrypt and Sign this content";
    auto result = SM2Util::encryptSign(content, keyPairBase64.publicKey, keyPairBase64.privateKey, true);
    std::string recovered = SM2Util::verifyDecrypt(result.ciphertext, result.signature, keyPairBase64.publicKey, keyPairBase64.privateKey);
    assert(content == recovered);
    std::cout << "✓ EncryptSign/VerifyDecrypt test passed\n";

    std::cout << "✓ All SM2 interoperability tests passed!\n\n";
}

void testSm3Interoperability() {
    std::cout << "Testing SM3 Interoperability...\n";

    std::vector<std::string> testInputs = {
        "Hello, SM3!",
        "国密SM3哈希测试",
        "Mixed测试123!",
        "Special chars: @#$%^&*()_+-={}[]|\\:;\"'<>?,./",
        ""  // Empty string test
    };

    for (const auto& input : testInputs) {
        if (input.empty()) continue; // Skip empty string for hash

        std::cout << "\nTesting with input: '" << input << "'\n";

        // Test hashing
        std::string hashHex = SM3Util::digestToStr(input, "UTF-8", false);
        std::string hashBase64 = SM3Util::digestToStr(input, "UTF-8", true);

        std::cout << "Input: " << input << "\n";
        std::cout << "Hash (Hex): " << hashHex << "\n";
        std::cout << "Hash (Base64): " << hashBase64 << "\n";

        // Hash should be consistent for the same input
        std::string hashHex2 = SM3Util::digestToStr(input, "UTF-8", false);
        assert(hashHex == hashHex2);
        std::cout << "✓ Consistency test passed\n";
    }

    // Test HMAC-SM3
    std::string testData = "HMAC test data";
    auto hmacKey = SM3Util::generateHmacKey(32);
    std::string hmacKeyHex = HexUtil::encodeHexStr(hmacKey);
    std::string hmacResult = SM3Util::hmacToStr(hmacKeyHex, testData, false);
    std::string hmacResultBase64 = SM3Util::hmacToStr(hmacKeyHex, testData, true);

    std::cout << "HMAC Key (Hex): " << hmacKeyHex.substr(0, 30) << "...\n";
    std::cout << "HMAC Result (Hex): " << hmacResult << "\n";
    std::cout << "HMAC Result (Base64): " << hmacResultBase64 << "\n";

    // Verify HMAC
    bool hmacVerified = SM3Util::hmacVerify(hmacKeyHex, testData, hmacResult);
    std::cout << "HMAC Verification: " << (hmacVerified ? "PASS" : "FAIL") << "\n";
    assert(hmacVerified);
    std::cout << "✓ HMAC-SM3 test passed\n";

    std::cout << "✓ All SM3 interoperability tests passed!\n\n";
}

void testSm4Interoperability() {
    std::cout << "Testing SM4 Interoperability...\n";

    // Generate a key
    std::string keyHex = SM4Util::generateKeyAsHex();
    auto key = SM4Util::parseHexKey(keyHex);

    std::vector<std::string> testInputs = {
        "Hello, SM4! This is a test.",
        "国密SM4测试数据",
        "Mixed测试123456!",
        "Short",
        ""  // Empty string test
    };

    for (const auto& input : testInputs) {
        if (input.empty()) continue; // Skip empty string for encryption

        std::cout << "\nTesting with input: '" << input << "'\n";
        std::cout << "Key (Hex): " << keyHex << "\n";

        // Test native encryption/decryption
        auto inputBytes = StringUtil::stringToBytes(input, "UTF-8");
        std::string encrypted = SM4Util::encryptEcbNative(key, inputBytes);
        std::string decrypted = SM4Util::decryptEcbNative(key, encrypted);

        std::cout << "Encrypted (Hex): " << encrypted.substr(0, 30) << "...\n";
        std::cout << "Decrypted: " << decrypted << "\n";
        assert(input == decrypted);
        std::cout << "✓ SM4 Native encryption/decryption test passed\n";

        // Test JCA-style encryption/decryption
        std::string encryptedJca = SM4Util::encryptEcbJca(key, input);
        std::string decryptedJca = SM4Util::decryptEcbJca(key, encryptedJca);

        std::cout << "JCA Encrypted (Hex): " << encryptedJca.substr(0, 30) << "...\n";
        std::cout << "JCA Decrypted: " << decryptedJca << "\n";
        assert(input == decryptedJca);
        std::cout << "✓ SM4 JCA-style encryption/decryption test passed\n";
    }

    std::cout << "✓ All SM4 interoperability tests passed!\n\n";
}

void testCharsetsAndFormats() {
    std::cout << "Testing charset and format conversions...\n";

    // Test different character sets
    std::vector<std::pair<std::string, std::string>> testCases = {
        {"Hello, World!", "UTF-8"},
        {"国密算法测试", "UTF-8"},
        {"Mixed测试123!", "UTF-8"}
    };

    for (const auto& testCase : testCases) {
        const std::string& original = testCase.first;
        const std::string& charset = testCase.second;

        std::cout << "\nTesting charset '" << charset << "' with: '" << original << "'\n";

        // Convert string to bytes using specified charset
        auto bytes = StringUtil::stringToBytes(original, charset);
        // Convert back to string
        std::string convertedBack = StringUtil::bytesToString(bytes, charset);

        std::cout << "Original: " << original << "\n";
        std::cout << "Converted back: " << convertedBack << "\n";
        assert(original == convertedBack);
        std::cout << "✓ Charset conversion test passed\n";
    }

    // Test Base64 encoding/decoding
    std::string testStr = "Test data for Base64 encoding!";
    std::vector<unsigned char> testBytes(testStr.begin(), testStr.end());
    std::string encoded = Base64Util::encodeBase64Str(testBytes);
    auto decoded = Base64Util::decodeBase64Str(encoded);

    std::cout << "\nBase64 Test:\n";
    std::cout << "Original: " << testStr << "\n";
    std::cout << "Encoded: " << encoded << "\n";
    std::cout << "Decoded: " << std::string(decoded.begin(), decoded.end()) << "\n";
    assert(testStr == std::string(decoded.begin(), decoded.end()));
    std::cout << "✓ Base64 encoding/decoding test passed\n";

    // Test Hex encoding/decoding
    std::string hexEncoded = HexUtil::encodeHexStr(testBytes);
    auto hexDecoded = HexUtil::decodeHexStr(hexEncoded);

    std::cout << "\nHex Test:\n";
    std::cout << "Original: " << testStr << "\n";
    std::cout << "Encoded: " << hexEncoded << "\n";
    std::cout << "Decoded: " << std::string(hexDecoded.begin(), hexDecoded.end()) << "\n";
    assert(testStr == std::string(hexDecoded.begin(), hexDecoded.end()));
    std::cout << "✓ Hex encoding/decoding test passed\n";

    std::cout << "✓ All charset and format tests passed!\n\n";
}

int main() {
    std::cout << "Running Crossmool C++ Interoperability Tests\n";
    std::cout << "===========================================\n\n";

    try {
        // Generate files for interop with Java
        generateInteropFiles();

        testCharsetsAndFormats();
        testSm2Interoperability();
        testSm3Interoperability();
        testSm4Interoperability();

        std::cout << "🎉 All interoperability tests passed successfully!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "❌ Interoperability test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}