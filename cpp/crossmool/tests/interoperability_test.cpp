#include <iostream>
#include <string>
#include <vector>
#include <cassert>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>

#include "SM2Util.h"
#include "SM3Util.h"
#include "SM4Util.h"
#include "HexUtil.h"
#include "Base64Util.h"
#include "StringUtil.h"

// 简单的 JSON 解析辅助函数
std::string readJsonFile(const std::string& filepath) {
    std::ifstream file(filepath);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void writeJsonFile(const std::string& filepath, const std::string& content) {
    std::ofstream file(filepath);
    file << content;
}

std::string extractJsonValue(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    
    pos = json.find("\"", pos);
    if (pos == std::string::npos) return "";
    
    size_t endPos = json.find("\"", pos + 1);
    if (endPos == std::string::npos) return "";
    
    return json.substr(pos + 1, endPos - pos - 1);
}

std::string extractNestedJsonValue(const std::string& json, const std::string& outerKey, const std::string& innerKey) {
    // 查找外层键，例如 "encryption_public_key"
    std::string outerSearchKey = "\"" + outerKey + "\"";
    size_t outerPos = json.find(outerSearchKey);
    if (outerPos == std::string::npos) return "";
    
    // 找到外层键后面的 {
    size_t bracePos = json.find("{", outerPos);
    if (bracePos == std::string::npos) return "";
    
    // 在内层查找 innerKey，例如 "hex"
    std::string innerSearchKey = "\"" + innerKey + "\"";
    size_t innerPos = json.find(innerSearchKey, bracePos);
    if (innerPos == std::string::npos) return "";
    
    // 找到 : 后面的 "
    size_t colonPos = json.find(":", innerPos);
    if (colonPos == std::string::npos) return "";
    
    size_t quotePos = json.find("\"", colonPos);
    if (quotePos == std::string::npos) return "";
    
    // 找到值结束的 "
    size_t endQuotePos = json.find("\"", quotePos + 1);
    if (endQuotePos == std::string::npos) return "";
    
    return json.substr(quotePos + 1, endQuotePos - quotePos - 1);
}

void runEncryptSignCommand(const std::string& inputFile, const std::string& keysFile, const std::string& outputFile) {
    // 读取输入内容
    std::ifstream inputStream(inputFile);
    std::stringstream inputBuffer;
    inputBuffer << inputStream.rdbuf();
    std::string content = inputBuffer.str();
    
    // 读取密钥文件
    std::string keysJson = readJsonFile(keysFile);
    
    // 提取公钥和私钥 - 从嵌套的 JSON 结构中读取
    std::string encPublicKey = extractNestedJsonValue(keysJson, "encryption_public_key", "hex");
    std::string signPrivateKey = extractNestedJsonValue(keysJson, "signature_private_key", "hex");
    
    if (encPublicKey.empty() || signPrivateKey.empty()) {
        std::cerr << "Error: Failed to extract keys from JSON file" << std::endl;
        return;
    }
    
    // 执行加密和签名
    try {
        auto result = SM2Util::encryptSign(content, encPublicKey, signPrivateKey, false);
        
        // 构建输出 JSON
        std::string outputJson = "{\n";
        outputJson += "  \"ciphertext_hex\": \"" + result.ciphertext + "\",\n";
        outputJson += "  \"signature_hex\": \"" + result.signature + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "Encryption and signature completed successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during encryption/signature: " << e.what() << std::endl;
    }
}

void runVerifyDecryptCommand(const std::string& inputFile, const std::string& keysFile, const std::string& outputFile) {
    // 读取输入 JSON 文件（包含 ciphertext_hex 和 signature_hex）
    std::string inputJson = readJsonFile(inputFile);
    
    // 提取密文和签名
    std::string ciphertext = extractJsonValue(inputJson, "ciphertext_hex");
    std::string signature = extractJsonValue(inputJson, "signature_hex");
    
    if (ciphertext.empty() || signature.empty()) {
        std::cerr << "Error: Failed to extract ciphertext or signature from input JSON" << std::endl;
        return;
    }
    
    // 读取密钥文件
    std::string keysJson = readJsonFile(keysFile);
    
    // 提取验签公钥和解密私钥
    std::string verifyPublicKey = extractNestedJsonValue(keysJson, "encryption_public_key", "hex");
    std::string decryptPrivateKey = extractNestedJsonValue(keysJson, "signature_private_key", "hex");
    
    if (verifyPublicKey.empty() || decryptPrivateKey.empty()) {
        std::cerr << "Error: Failed to extract keys from JSON file" << std::endl;
        return;
    }
    
    // 执行验签和解密
    try {
        std::string plaintext = SM2Util::verifyDecrypt(ciphertext, signature, verifyPublicKey, decryptPrivateKey);
        
        // 构建输出 JSON
        std::string outputJson = "{\n";
        outputJson += "  \"decrypted_text\": \"" + plaintext + "\",\n";
        outputJson += "  \"verify_result\": true\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "Verification and decryption completed successfully.\n";
        std::cout << "Decrypted text: " << plaintext << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during verification/decryption: " << e.what() << std::endl;
        
        // 构建错误输出 JSON
        std::string outputJson = "{\n";
        outputJson += "  \"decrypted_text\": \"\",\n";
        outputJson += "  \"verify_result\": false,\n";
        outputJson += "  \"error\": \"" + std::string(e.what()) + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
    }
}

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <command> <arguments>\n";
    std::cout << "Commands:\n";
    std::cout << "  encrypt_sign <input_file> <keys_file> <output_file>\n";
    std::cout << "    - input_file: 输入文本文件（UTF-8 编码）\n";
    std::cout << "    - keys_file:  密钥 JSON 文件，包含 encryption_public_key.hex 和 signature_private_key.hex\n";
    std::cout << "    - output_file: 输出 JSON 文件，包含 ciphertext_hex 和 signature_hex\n";
    std::cout << "\n  verify_decrypt <input_file> <keys_file> <output_file>\n";
    std::cout << "    - input_file:  输入 JSON 文件，包含 ciphertext_hex 和 signature_hex\n";
    std::cout << "    - keys_file:   密钥 JSON 文件，包含 encryption_public_key.hex 和 signature_private_key.hex\n";
    std::cout << "    - output_file: 输出 JSON 文件，包含 decrypted_text 和 verify_result\n";
    std::cout << "\n  test\n";
    std::cout << "    - 运行完整的互操作性测试（默认行为）\n";
}

void generateInteropFiles() {
    std::cout << "Generating interop test files for Java counterpart...\n";

    auto keyPair = SM2Util::generateKeyPairHex();
    std::vector<unsigned char> pubKeyDer = HexUtil::decodeHexStr(keyPair.publicKey);
    std::vector<unsigned char> privKeyDer = HexUtil::decodeHexStr(keyPair.privateKey);

    std::ofstream pubDerFile("interop_test_public.der", std::ios::binary);
    pubDerFile.write(reinterpret_cast<const char*>(pubKeyDer.data()), pubKeyDer.size());
    pubDerFile.close();

    std::ofstream privDerFile("interop_test_private.der", std::ios::binary);
    privDerFile.write(reinterpret_cast<const char*>(privKeyDer.data()), privKeyDer.size());
    privDerFile.close();

    std::string message = "interoperability-test-message";
    std::string cipherHex = SM2Util::encrypt(message, keyPair.publicKey, false);
    std::string sigHex = SM2Util::sign(message, keyPair.privateKey, false);

    std::ofstream cipherFile("interop_test_cipher.hex");
    cipherFile << cipherHex;
    cipherFile.close();

    std::ofstream sigFile("interop_test_signature.hex");
    sigFile << sigHex;
    sigFile.close();

    std::cout << "Generated interop test files:\n";
}

void testSm2Interoperability() {
    std::cout << "Testing SM2 Interoperability...\n";

    auto keyPairBase64 = SM2Util::generateKeyPairBase64();
    auto keyPairHex = SM2Util::generateKeyPairHex();

    std::vector<std::string> testInputs = {
        "Hello, SM2!",
        "国密算法测试",
        "Mixed 测试 123!",
        ""
    };

    for (const auto& input : testInputs) {
        std::string encryptedHex = SM2Util::encrypt(input, keyPairHex.publicKey, false);
        std::string decryptedHex = SM2Util::decrypt(encryptedHex, keyPairHex.privateKey);
        assert(input == decryptedHex);
    }

    for (const auto& input : testInputs) {
        if (input.empty()) continue;
        std::string signatureHex = SM2Util::sign(input, keyPairHex.privateKey, false);
        bool verifiedHex = SM2Util::verify(input, keyPairHex.publicKey, signatureHex);
        assert(verifiedHex);
    }

    std::string content = "Encrypt and Sign this content";
    auto result = SM2Util::encryptSign(content, keyPairBase64.publicKey, keyPairBase64.privateKey, true);
    std::string recovered = SM2Util::verifyDecrypt(result.ciphertext, result.signature, keyPairBase64.publicKey, keyPairBase64.privateKey);
    assert(content == recovered);

    std::cout << "All SM2 interoperability tests passed!\n\n";
}

void testSm3Interoperability() {
    std::cout << "Testing SM3 Interoperability...\n";

    std::vector<std::string> testInputs = {
        "Hello, SM3!",
        "国密 SM3 哈希测试",
        ""
    };

    for (const auto& input : testInputs) {
        if (input.empty()) continue;
        std::string hashHex = SM3Util::digestToStr(input, "UTF-8", false);
        std::string hashHex2 = SM3Util::digestToStr(input, "UTF-8", false);
        assert(hashHex == hashHex2);
    }

    std::cout << "All SM3 interoperability tests passed!\n\n";
}

void testSm4Interoperability() {
    std::cout << "Testing SM4 Interoperability...\n";

    std::string keyHex = SM4Util::generateKeyAsHex();
    auto key = SM4Util::parseHexKey(keyHex);

    std::vector<std::string> testInputs = {
        "Hello, SM4! This is a test.",
        "国密 SM4 测试数据",
        ""
    };

    for (const auto& input : testInputs) {
        if (input.empty()) continue;
        auto inputBytes = StringUtil::stringToBytes(input, "UTF-8");
        std::string encrypted = SM4Util::encryptEcbNative(key, inputBytes);
        std::string decrypted = SM4Util::decryptEcbNative(key, encrypted);
        assert(input == decrypted);
    }

    std::cout << "All SM4 interoperability tests passed!\n\n";
}

void testCharsetsAndFormats() {
    std::cout << "Testing charset and format conversions...\n";

    std::vector<std::pair<std::string, std::string>> testCases = {
        {"Hello, World!", "UTF-8"},
        {"国密算法测试", "UTF-8"}
    };

    for (const auto& testCase : testCases) {
        const std::string& original = testCase.first;
        const std::string& charset = testCase.second;
        auto bytes = StringUtil::stringToBytes(original, charset);
        std::string convertedBack = StringUtil::bytesToString(bytes, charset);
        assert(original == convertedBack);
    }

    std::string testStr = "Test data for Base64 encoding!";
    std::vector<unsigned char> testBytes(testStr.begin(), testStr.end());
    std::string encoded = Base64Util::encodeBase64Str(testBytes);
    auto decoded = Base64Util::decodeBase64Str(encoded);
    assert(testStr == std::string(decoded.begin(), decoded.end()));

    std::string hexEncoded = HexUtil::encodeHexStr(testBytes);
    auto hexDecoded = HexUtil::decodeHexStr(hexEncoded);
    assert(testStr == std::string(hexDecoded.begin(), hexDecoded.end()));

    std::cout << "All charset and format tests passed!\n\n";
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        std::string command = argv[1];
        
        if (command == "encrypt_sign") {
            if (argc != 5) {
                std::cerr << "Error: encrypt_sign command requires 3 arguments\n";
                printUsage(argv[0]);
                return 1;
            }
            
            try {
                runEncryptSignCommand(argv[2], argv[3], argv[4]);
                std::cout << "Command completed successfully" << std::endl;
                return 0;
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
                return 1;
            }
        } else if (command == "verify_decrypt") {
            if (argc != 5) {
                std::cerr << "Error: verify_decrypt command requires 3 arguments\n";
                printUsage(argv[0]);
                return 1;
            }
            
            try {
                runVerifyDecryptCommand(argv[2], argv[3], argv[4]);
                std::cout << "Command completed successfully" << std::endl;
                return 0;
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
                return 1;
            }
        } else if (command == "test") {
            // 运行完整的互操作性测试
        } else if (command == "--help" || command == "-h") {
            printUsage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown command: " << command << "\n";
            printUsage(argv[0]);
            return 1;
        }
    }
    
    std::cout << "Running Crossmool C++ Interoperability Tests\n";
    std::cout << "===========================================\n\n";

    try {
        generateInteropFiles();
        testCharsetsAndFormats();
        testSm2Interoperability();
        testSm3Interoperability();
        testSm4Interoperability();

        std::cout << "All interoperability tests passed successfully!\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Interoperability test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}