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

// ======================================================================
// JSON 辅助函数（轻量级，无第三方依赖）
// ======================================================================

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

/**
 * 从 JSON 中提取顶层字符串字段值
 * 例如：{"foo": "bar"} -> extractJsonValue(json, "foo") -> "bar"
 */
std::string extractJsonValue(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";
    
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    
    // Skip whitespace
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) pos++;

    // Handle boolean or null
    if (pos < json.size() && json[pos] != '"') {
        size_t endPos = json.find_first_of(",}\n", pos);
        if (endPos == std::string::npos) endPos = json.size();
        return json.substr(pos, endPos - pos);
    }

    // String value
    size_t quoteStart = pos; // pos is at '"'
    size_t endPos = json.find("\"", quoteStart + 1);
    if (endPos == std::string::npos) return "";
    
    return json.substr(quoteStart + 1, endPos - quoteStart - 1);
}

/**
 * 从嵌套 JSON 对象中提取字段值
 * 例如：{"outer": {"inner": "value"}} -> extractNestedJsonValue(json, "outer", "inner") -> "value"
 */
std::string extractNestedJsonValue(const std::string& json, const std::string& outerKey, const std::string& innerKey) {
    std::string outerSearchKey = "\"" + outerKey + "\"";
    size_t outerPos = json.find(outerSearchKey);
    if (outerPos == std::string::npos) return "";
    
    size_t bracePos = json.find("{", outerPos);
    if (bracePos == std::string::npos) return "";
    
    // Find the end of this nested object
    size_t braceEnd = bracePos + 1;
    int depth = 1;
    while (braceEnd < json.size() && depth > 0) {
        if (json[braceEnd] == '{') depth++;
        else if (json[braceEnd] == '}') depth--;
        braceEnd++;
    }
    
    // Extract nested JSON substring
    std::string nestedJson = json.substr(bracePos, braceEnd - bracePos);
    return extractJsonValue(nestedJson, innerKey);
}

// ======================================================================
// SM2 加密+签名 命令
// ======================================================================

void runEncryptSignCommand(const std::string& inputFile, const std::string& keysFile, const std::string& outputFile) {
    // 读取输入内容
    std::ifstream inputStream(inputFile);
    std::stringstream inputBuffer;
    inputBuffer << inputStream.rdbuf();
    std::string content = inputBuffer.str();
    
    // 读取密钥文件
    std::string keysJson = readJsonFile(keysFile);
    
    // 提取加密公钥和签名私钥（嵌套 JSON 结构）
    std::string encPublicKey = extractNestedJsonValue(keysJson, "encryption_public_key", "hex");
    std::string signPrivateKey = extractNestedJsonValue(keysJson, "signature_private_key", "hex");
    
    if (encPublicKey.empty() || signPrivateKey.empty()) {
        std::cerr << "Error: Failed to extract keys from JSON file" << std::endl;
        std::cerr << "  encryption_public_key.hex: " << (encPublicKey.empty() ? "MISSING" : "OK") << std::endl;
        std::cerr << "  signature_private_key.hex: " << (signPrivateKey.empty() ? "MISSING" : "OK") << std::endl;
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
        std::string outputJson = "{\n";
        outputJson += "  \"ciphertext_hex\": \"\",\n";
        outputJson += "  \"signature_hex\": \"\",\n";
        outputJson += "  \"error\": \"" + std::string(e.what()) + "\"\n";
        outputJson += "}\n";
        writeJsonFile(outputFile, outputJson);
    }
}

// ======================================================================
// SM2 验签+解密 命令
// 密钥文件格式：
//   {
//     "encryption_private_key": {"hex": "..."},   <- 用于解密
//     "signature_public_key":   {"hex": "..."}    <- 用于验签
//   }
// ======================================================================

void runVerifyDecryptCommand(const std::string& inputFile, const std::string& keysFile, const std::string& outputFile) {
    std::string inputJson = readJsonFile(inputFile);
    
    std::string ciphertext = extractJsonValue(inputJson, "ciphertext_hex");
    std::string signature  = extractJsonValue(inputJson, "signature_hex");
    
    if (ciphertext.empty() || signature.empty()) {
        std::cerr << "Error: Failed to extract ciphertext or signature from input JSON" << std::endl;
        return;
    }
    
    std::string keysJson = readJsonFile(keysFile);
    
    // 解密私钥 = encryption_private_key，验签公钥 = signature_public_key
    // 但当只有单密钥对（同一对用于加密和签名）时，两者相同，使用 encryption_public_key / encryption_private_key
    std::string verifyPublicKey  = extractNestedJsonValue(keysJson, "signature_public_key", "hex");
    std::string decryptPrivateKey = extractNestedJsonValue(keysJson, "encryption_private_key", "hex");
    
    // 兼容只有 encryption_public_key / signature_private_key 的旧格式（单密钥对场景）
    if (verifyPublicKey.empty()) {
        verifyPublicKey = extractNestedJsonValue(keysJson, "encryption_public_key", "hex");
    }
    if (decryptPrivateKey.empty()) {
        decryptPrivateKey = extractNestedJsonValue(keysJson, "signature_private_key", "hex");
    }
    
    if (verifyPublicKey.empty() || decryptPrivateKey.empty()) {
        std::cerr << "Error: Failed to extract keys from JSON file" << std::endl;
        std::cerr << "  verify_public_key: " << (verifyPublicKey.empty() ? "MISSING" : "OK") << std::endl;
        std::cerr << "  decrypt_private_key: " << (decryptPrivateKey.empty() ? "MISSING" : "OK") << std::endl;
        return;
    }
    
    try {
        std::string plaintext = SM2Util::verifyDecrypt(ciphertext, signature, verifyPublicKey, decryptPrivateKey);
        
        std::string outputJson = "{\n";
        outputJson += "  \"decrypted_text\": \"" + plaintext + "\",\n";
        outputJson += "  \"verify_result\": true\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "Verification and decryption completed successfully.\n";
        std::cout << "Decrypted text: " << plaintext << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during verification/decryption: " << e.what() << std::endl;
        
        std::string outputJson = "{\n";
        outputJson += "  \"decrypted_text\": \"\",\n";
        outputJson += "  \"verify_result\": false,\n";
        outputJson += "  \"error\": \"" + std::string(e.what()) + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
    }
}

// ======================================================================
// SM3 Digest 命令
// 输入文件：纯文本
// 输出文件：{"digest_hex": "..."}
// ======================================================================

void runSm3DigestCommand(const std::string& inputFile, const std::string& outputFile) {
    std::ifstream inputStream(inputFile);
    std::stringstream inputBuffer;
    inputBuffer << inputStream.rdbuf();
    std::string content = inputBuffer.str();
    
    try {
        std::string digestHex = SM3Util::digestToStr(content, "UTF-8", false);
        
        std::string outputJson = "{\n";
        outputJson += "  \"digest_hex\": \"" + digestHex + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "SM3 digest computed: " << digestHex << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during SM3 digest: " << e.what() << std::endl;
    }
}

// ======================================================================
// SM3 HMAC 命令
// 输入文件：{"hmac_key_hex": "...", "data": "..."}
// 输出文件：{"hmac_hex": "..."}
// ======================================================================

void runSm3HmacCommand(const std::string& inputFile, const std::string& outputFile) {
    std::string inputJson = readJsonFile(inputFile);
    
    std::string keyHex = extractJsonValue(inputJson, "hmac_key_hex");
    std::string data   = extractJsonValue(inputJson, "data");
    
    if (keyHex.empty()) {
        std::cerr << "Error: hmac_key_hex not found in input JSON" << std::endl;
        return;
    }
    
    try {
        auto keyBytes  = HexUtil::decodeHexStr(keyHex);
        auto dataBytes = StringUtil::stringToBytes(data, "UTF-8");
        std::string hmacHex = SM3Util::hmacToStr(keyBytes, dataBytes, false);
        
        std::string outputJson = "{\n";
        outputJson += "  \"hmac_hex\": \"" + hmacHex + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "SM3 HMAC computed: " << hmacHex << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during SM3 HMAC: " << e.what() << std::endl;
    }
}

// ======================================================================
// SM4 ECB 加密 命令
// 输入文件：{"sm4_key_hex": "...", "plaintext": "..."}
// 输出文件：{"ciphertext_hex": "..."}
// ======================================================================

void runSm4EncryptCommand(const std::string& inputFile, const std::string& outputFile) {
    std::string inputJson = readJsonFile(inputFile);
    
    std::string keyHex    = extractJsonValue(inputJson, "sm4_key_hex");
    std::string plaintext = extractJsonValue(inputJson, "plaintext");
    
    if (keyHex.empty()) {
        std::cerr << "Error: sm4_key_hex not found in input JSON" << std::endl;
        return;
    }
    
    try {
        auto key = SM4Util::parseHexKey(keyHex);
        std::string ciphertextHex = SM4Util::encryptEcbJca(key, plaintext);
        
        std::string outputJson = "{\n";
        outputJson += "  \"ciphertext_hex\": \"" + ciphertextHex + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "SM4 ECB encrypt completed: " << ciphertextHex << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during SM4 ECB encrypt: " << e.what() << std::endl;
    }
}

// ======================================================================
// SM4 ECB 解密 命令
// 输入文件：{"sm4_key_hex": "...", "ciphertext_hex": "..."}
// 输出文件：{"plaintext": "..."}
// ======================================================================

void runSm4DecryptCommand(const std::string& inputFile, const std::string& outputFile) {
    std::string inputJson = readJsonFile(inputFile);
    
    std::string keyHex       = extractJsonValue(inputJson, "sm4_key_hex");
    std::string ciphertextHex = extractJsonValue(inputJson, "ciphertext_hex");
    
    if (keyHex.empty() || ciphertextHex.empty()) {
        std::cerr << "Error: sm4_key_hex or ciphertext_hex not found in input JSON" << std::endl;
        return;
    }
    
    try {
        auto key = SM4Util::parseHexKey(keyHex);
        std::string plaintext = SM4Util::decryptEcbJca(key, ciphertextHex);
        
        // Escape special characters for JSON
        std::string escaped;
        for (char c : plaintext) {
            if (c == '"')       escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else if (c == '\n') escaped += "\\n";
            else if (c == '\r') escaped += "\\r";
            else if (c == '\t') escaped += "\\t";
            else                escaped += c;
        }
        
        std::string outputJson = "{\n";
        outputJson += "  \"plaintext\": \"" + escaped + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "SM4 ECB decrypt completed: " << plaintext << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during SM4 ECB decrypt: " << e.what() << std::endl;
    }
}

// ======================================================================
// SM2 仅加密命令（不含签名）
// 输入文件：纯文本
// 密钥文件：{"encryption_public_key": {"hex": "..."}}
// 输出文件：{"ciphertext_hex": "..."}
// ======================================================================

void runEncryptOnlyCommand(const std::string& inputFile, const std::string& keysFile, const std::string& outputFile) {
    std::ifstream inputStream(inputFile);
    std::stringstream inputBuffer;
    inputBuffer << inputStream.rdbuf();
    std::string content = inputBuffer.str();
    
    std::string keysJson = readJsonFile(keysFile);
    std::string encPublicKey = extractNestedJsonValue(keysJson, "encryption_public_key", "hex");
    
    if (encPublicKey.empty()) {
        std::cerr << "Error: encryption_public_key.hex not found" << std::endl;
        return;
    }
    
    try {
        std::string ciphertextHex = SM2Util::encryptToHex(content, encPublicKey);
        
        std::string outputJson = "{\n";
        outputJson += "  \"ciphertext_hex\": \"" + ciphertextHex + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "SM2 encrypt completed.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during SM2 encrypt: " << e.what() << std::endl;
    }
}

// ======================================================================
// SM2 仅解密命令（不含验签）
// 输入文件：{"ciphertext_hex": "..."}
// 密钥文件：{"encryption_private_key": {"hex": "..."}}
// 输出文件：{"plaintext": "..."}
// ======================================================================

void runDecryptOnlyCommand(const std::string& inputFile, const std::string& keysFile, const std::string& outputFile) {
    std::string inputJson = readJsonFile(inputFile);
    std::string ciphertextHex = extractJsonValue(inputJson, "ciphertext_hex");
    
    if (ciphertextHex.empty()) {
        std::cerr << "Error: ciphertext_hex not found in input JSON" << std::endl;
        return;
    }
    
    std::string keysJson = readJsonFile(keysFile);
    std::string decPrivateKey = extractNestedJsonValue(keysJson, "encryption_private_key", "hex");
    if (decPrivateKey.empty()) {
        // Fallback: use signature_private_key if only one key pair
        decPrivateKey = extractNestedJsonValue(keysJson, "signature_private_key", "hex");
    }
    
    if (decPrivateKey.empty()) {
        std::cerr << "Error: encryption_private_key.hex not found" << std::endl;
        return;
    }
    
    try {
        std::string plaintext = SM2Util::decrypt(ciphertextHex, decPrivateKey);
        
        // Escape special characters for JSON
        std::string escaped;
        for (char c : plaintext) {
            if (c == '"')       escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else if (c == '\n') escaped += "\\n";
            else if (c == '\r') escaped += "\\r";
            else if (c == '\t') escaped += "\\t";
            else                escaped += c;
        }
        
        std::string outputJson = "{\n";
        outputJson += "  \"plaintext\": \"" + escaped + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "SM2 decrypt completed: " << plaintext << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during SM2 decrypt: " << e.what() << std::endl;
        std::string outputJson = "{\n";
        outputJson += "  \"plaintext\": \"\",\n";
        outputJson += "  \"error\": \"" + std::string(e.what()) + "\"\n";
        outputJson += "}\n";
        writeJsonFile(outputFile, outputJson);
    }
}

// ======================================================================
// SM2 仅签名命令
// 输入文件：纯文本
// 密钥文件：{"signature_private_key": {"hex": "..."}}
// 输出文件：{"signature_hex": "..."}
// ======================================================================

void runSignOnlyCommand(const std::string& inputFile, const std::string& keysFile, const std::string& outputFile) {
    std::ifstream inputStream(inputFile);
    std::stringstream inputBuffer;
    inputBuffer << inputStream.rdbuf();
    std::string content = inputBuffer.str();
    
    std::string keysJson = readJsonFile(keysFile);
    std::string signPrivateKey = extractNestedJsonValue(keysJson, "signature_private_key", "hex");
    
    if (signPrivateKey.empty()) {
        std::cerr << "Error: signature_private_key.hex not found" << std::endl;
        return;
    }
    
    try {
        std::string signatureHex = SM2Util::signToHex(content, signPrivateKey);
        
        std::string outputJson = "{\n";
        outputJson += "  \"signature_hex\": \"" + signatureHex + "\"\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "SM2 sign completed: " << signatureHex << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during SM2 sign: " << e.what() << std::endl;
    }
}

// ======================================================================
// SM2 仅验签命令
// 输入文件：{"content": "...", "signature_hex": "..."}
// 密钥文件：{"signature_public_key": {"hex": "..."}}
// 输出文件：{"verify_result": true/false}
// ======================================================================

void runVerifyOnlyCommand(const std::string& inputFile, const std::string& keysFile, const std::string& outputFile) {
    std::string inputJson = readJsonFile(inputFile);
    std::string content      = extractJsonValue(inputJson, "content");
    std::string signatureHex = extractJsonValue(inputJson, "signature_hex");
    
    if (signatureHex.empty()) {
        std::cerr << "Error: signature_hex not found in input JSON" << std::endl;
        return;
    }
    
    std::string keysJson = readJsonFile(keysFile);
    std::string verifyPublicKey = extractNestedJsonValue(keysJson, "signature_public_key", "hex");
    if (verifyPublicKey.empty()) {
        verifyPublicKey = extractNestedJsonValue(keysJson, "encryption_public_key", "hex");
    }
    
    if (verifyPublicKey.empty()) {
        std::cerr << "Error: signature_public_key.hex not found" << std::endl;
        return;
    }
    
    try {
        bool result = SM2Util::verify(content, verifyPublicKey, signatureHex);
        
        std::string outputJson = "{\n";
        outputJson += "  \"verify_result\": " + std::string(result ? "true" : "false") + "\n";
        outputJson += "}\n";
        
        writeJsonFile(outputFile, outputJson);
        std::cout << "SM2 verify result: " << (result ? "true" : "false") << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Error during SM2 verify: " << e.what() << std::endl;
        std::string outputJson = "{\n";
        outputJson += "  \"verify_result\": false,\n";
        outputJson += "  \"error\": \"" + std::string(e.what()) + "\"\n";
        outputJson += "}\n";
        writeJsonFile(outputFile, outputJson);
    }
}

// ======================================================================
// Usage
// ======================================================================

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <command> <arguments>\n\n";
    std::cout << "SM2 Commands:\n";
    std::cout << "  encrypt_sign <input_txt> <keys_json> <output_json>\n";
    std::cout << "    keys_json: {encryption_public_key:{hex:...}, signature_private_key:{hex:...}}\n";
    std::cout << "    output:    {ciphertext_hex, signature_hex}\n\n";
    std::cout << "  verify_decrypt <input_json> <keys_json> <output_json>\n";
    std::cout << "    input:     {ciphertext_hex, signature_hex}\n";
    std::cout << "    keys_json: {signature_public_key:{hex:...}, encryption_private_key:{hex:...}}\n";
    std::cout << "    output:    {decrypted_text, verify_result}\n\n";
    std::cout << "  encrypt <input_txt> <keys_json> <output_json>\n";
    std::cout << "    keys_json: {encryption_public_key:{hex:...}}\n";
    std::cout << "    output:    {ciphertext_hex}\n\n";
    std::cout << "  decrypt <input_json> <keys_json> <output_json>\n";
    std::cout << "    input:     {ciphertext_hex}\n";
    std::cout << "    keys_json: {encryption_private_key:{hex:...}}\n";
    std::cout << "    output:    {plaintext}\n\n";
    std::cout << "  sign <input_txt> <keys_json> <output_json>\n";
    std::cout << "    keys_json: {signature_private_key:{hex:...}}\n";
    std::cout << "    output:    {signature_hex}\n\n";
    std::cout << "  verify <input_json> <keys_json> <output_json>\n";
    std::cout << "    input:     {content, signature_hex}\n";
    std::cout << "    keys_json: {signature_public_key:{hex:...}}\n";
    std::cout << "    output:    {verify_result}\n\n";
    std::cout << "SM3 Commands:\n";
    std::cout << "  sm3_digest <input_txt> <output_json>\n";
    std::cout << "    output:    {digest_hex}\n\n";
    std::cout << "  sm3_hmac <input_json> <output_json>\n";
    std::cout << "    input:     {hmac_key_hex, data}\n";
    std::cout << "    output:    {hmac_hex}\n\n";
    std::cout << "SM4 Commands:\n";
    std::cout << "  sm4_encrypt <input_json> <output_json>\n";
    std::cout << "    input:     {sm4_key_hex, plaintext}\n";
    std::cout << "    output:    {ciphertext_hex}\n\n";
    std::cout << "  sm4_decrypt <input_json> <output_json>\n";
    std::cout << "    input:     {sm4_key_hex, ciphertext_hex}\n";
    std::cout << "    output:    {plaintext}\n\n";
    std::cout << "  test\n";
    std::cout << "    Run built-in self-tests\n";
}

// ======================================================================
// 内置自测
// ======================================================================

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
    std::string cipherHex = SM2Util::encryptToHex(message, keyPair.publicKey);
    std::string sigHex = SM2Util::signToHex(message, keyPair.privateKey);

    std::ofstream cipherFile("interop_test_cipher.hex");
    cipherFile << cipherHex;
    cipherFile.close();

    std::ofstream sigFile("interop_test_signature.hex");
    sigFile << sigHex;
    sigFile.close();

    std::cout << "Generated interop test files.\n";
}

void testSm2Interoperability() {
    std::cout << "Testing SM2 Interoperability...\n";

    auto keyPairBase64 = SM2Util::generateKeyPairBase64();
    auto keyPairHex = SM2Util::generateKeyPairHex();

    std::vector<std::string> testInputs = {
        "Hello, SM2!",
        "\xe5\x9b\xbd\xe5\xaf\x86\xe7\xae\x97\xe6\xb3\x95\xe6\xb5\x8b\xe8\xaf\x95",  // 国密算法测试
        "Mixed test 123!",
        ""
    };

    for (const auto& input : testInputs) {
        std::string encryptedHex = SM2Util::encryptToHex(input, keyPairHex.publicKey);
        std::string decryptedHex = SM2Util::decrypt(encryptedHex, keyPairHex.privateKey);
        assert(input == decryptedHex);
    }

    for (const auto& input : testInputs) {
        if (input.empty()) continue;
        std::string signatureHex = SM2Util::signToHex(input, keyPairHex.privateKey);
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
        "\xe5\x9b\xbd\xe5\xaf\x86 SM3 \xe5\x93\x88\xe5\x96\x8c\xe6\xb5\x8b\xe8\xaf\x95",  // 国密 SM3 哈希测试
    };

    for (const auto& input : testInputs) {
        std::string hashHex = SM3Util::digestToStr(input, "UTF-8", false);
        std::string hashHex2 = SM3Util::digestToStr(input, "UTF-8", false);
        assert(hashHex == hashHex2);
        assert(hashHex.length() == 64);  // 32 bytes = 64 hex chars
    }

    // Test HMAC
    std::string key = "0d4557e5ed4b01d2bb05853e16886d82c6d5d44b3ef1958cadbdc2cd4752093c";
    auto keyBytes = HexUtil::decodeHexStr(key);
    std::string data = "Hello, HMAC test";
    auto dataBytes = StringUtil::stringToBytes(data, "UTF-8");
    std::string hmac1 = SM3Util::hmacToStr(keyBytes, dataBytes, false);
    std::string hmac2 = SM3Util::hmacToStr(keyBytes, dataBytes, false);
    assert(hmac1 == hmac2);
    assert(hmac1.length() == 64);

    std::cout << "All SM3 interoperability tests passed!\n\n";
}

void testSm4Interoperability() {
    std::cout << "Testing SM4 Interoperability...\n";

    std::string keyHex = SM4Util::generateKeyAsHex();
    auto key = SM4Util::parseHexKey(keyHex);

    std::vector<std::string> testInputs = {
        "Hello, SM4! This is a test.",
        "\xe5\x9b\xbd\xe5\xaf\x86 SM4 \xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae",  // 国密 SM4 测试数据
    };

    for (const auto& input : testInputs) {
        auto inputBytes = StringUtil::stringToBytes(input, "UTF-8");
        std::string encrypted = SM4Util::encryptEcbNative(key, inputBytes);
        std::string decrypted = SM4Util::decryptEcbNative(key, encrypted);
        assert(input == decrypted);
    }

    // Test with fixed Java test key
    std::string javaKeyHex = "8091d00c09ba74cfe6da26b7daa7ce39";
    auto javaKey = SM4Util::parseHexKey(javaKeyHex);
    std::string plaintext = "Hello, \xe9\x80\x99\xe6\x98\xaf\xe5\x9b\xbd\xe5\xaf\x86SM4\xe6\xb8\xac\xe8\xa9\xa6\xe6\x95\xb8\xe6\x93\x9a";  // Hello, 這是国密SM4測試數據
    auto ptBytes = StringUtil::stringToBytes(plaintext, "UTF-8");
    std::string cipher = SM4Util::encryptEcbNative(javaKey, ptBytes);
    std::string recovered = SM4Util::decryptEcbNative(javaKey, cipher);
    assert(plaintext == recovered);

    std::cout << "All SM4 interoperability tests passed!\n\n";
}

void testCharsetsAndFormats() {
    std::cout << "Testing charset and format conversions...\n";

    std::vector<std::pair<std::string, std::string>> testCases = {
        {"Hello, World!", "UTF-8"},
        {"\xe5\x9b\xbd\xe5\xaf\x86\xe7\xae\x97\xe6\xb3\x95\xe6\xb5\x8b\xe8\xaf\x95", "UTF-8"}  // 国密算法测试
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

// ======================================================================
// main
// ======================================================================

int main(int argc, char* argv[]) {
    if (argc > 1) {
        std::string command = argv[1];
        
        try {
            if (command == "encrypt_sign") {
                if (argc != 5) { std::cerr << "encrypt_sign requires 3 arguments\n"; printUsage(argv[0]); return 1; }
                runEncryptSignCommand(argv[2], argv[3], argv[4]);
                return 0;
            } else if (command == "verify_decrypt") {
                if (argc != 5) { std::cerr << "verify_decrypt requires 3 arguments\n"; printUsage(argv[0]); return 1; }
                runVerifyDecryptCommand(argv[2], argv[3], argv[4]);
                return 0;
            } else if (command == "encrypt") {
                if (argc != 5) { std::cerr << "encrypt requires 3 arguments\n"; printUsage(argv[0]); return 1; }
                runEncryptOnlyCommand(argv[2], argv[3], argv[4]);
                return 0;
            } else if (command == "decrypt") {
                if (argc != 5) { std::cerr << "decrypt requires 3 arguments\n"; printUsage(argv[0]); return 1; }
                runDecryptOnlyCommand(argv[2], argv[3], argv[4]);
                return 0;
            } else if (command == "sign") {
                if (argc != 5) { std::cerr << "sign requires 3 arguments\n"; printUsage(argv[0]); return 1; }
                runSignOnlyCommand(argv[2], argv[3], argv[4]);
                return 0;
            } else if (command == "verify") {
                if (argc != 5) { std::cerr << "verify requires 3 arguments\n"; printUsage(argv[0]); return 1; }
                runVerifyOnlyCommand(argv[2], argv[3], argv[4]);
                return 0;
            } else if (command == "sm3_digest") {
                if (argc != 4) { std::cerr << "sm3_digest requires 2 arguments\n"; printUsage(argv[0]); return 1; }
                runSm3DigestCommand(argv[2], argv[3]);
                return 0;
            } else if (command == "sm3_hmac") {
                if (argc != 4) { std::cerr << "sm3_hmac requires 2 arguments\n"; printUsage(argv[0]); return 1; }
                runSm3HmacCommand(argv[2], argv[3]);
                return 0;
            } else if (command == "sm4_encrypt") {
                if (argc != 4) { std::cerr << "sm4_encrypt requires 2 arguments\n"; printUsage(argv[0]); return 1; }
                runSm4EncryptCommand(argv[2], argv[3]);
                return 0;
            } else if (command == "sm4_decrypt") {
                if (argc != 4) { std::cerr << "sm4_decrypt requires 2 arguments\n"; printUsage(argv[0]); return 1; }
                runSm4DecryptCommand(argv[2], argv[3]);
                return 0;
            } else if (command == "test") {
                // Fall through to run tests
            } else if (command == "--help" || command == "-h") {
                printUsage(argv[0]);
                return 0;
            } else {
                std::cerr << "Unknown command: " << command << "\n";
                printUsage(argv[0]);
                return 1;
            }
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
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
