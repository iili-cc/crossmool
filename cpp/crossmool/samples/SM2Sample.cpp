/**
 * SM2 国密非对称加密算法示例
 *
 * 快速上手：
 * 1. 确保已安装 CMake >= 3.20 和 C++20 编译器（MSVC / GCC / Clang）
 * 2. cd cpp/crossmool && mkdir build && cd build
 * 3. cmake .. && cmake --build .
 * 4. 运行：./bin/sm2_sample  (或 build\bin\Release\sm2_sample.exe)
 *
 * 核心能力：
 * - 生成 SM2 密钥对（Hex / Base64 / Raw DER）
 * - 公钥加密 → 私钥解密
 * - 私钥签名 → 公钥验签
 * - 先加密再签名 → 先验签再解密（防篡改 + 防抵赖）
 * - PEM 格式导入导出
 */

#include <iostream>
#include <string>
#include "SM2Util.h"

int main()
{
    std::cout << "============================================================" << std::endl;
    std::cout << "  SM2 Sample — 国密非对称加密 (SM2P256V1)" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;

    // ==================== 原始内容 ====================
    std::string originalContent =
        "今天天气真好，气温大约 28°C，我决定出門走走。"
        "路过咖啡店时買了一杯美式，順便（顺便）看了下手机。"
        "Don't forget to bring your umbrella!";

    std::cout << "OriginalContent ::: " << originalContent << std::endl;
    std::cout << std::endl;

    // ==================== 1. 生成两对密钥 ====================
    std::cout << ">>> 1. 生成两对 SM2 密钥（第1对加解密，第2对签名）" << std::endl;

    auto [pubKey1, priKey1] = SM2Util::generateKeyPairHex();
    auto [pubKey2, priKey2] = SM2Util::generateKeyPairHex();

    std::cout << "  privateKeyHex-1 ::: " << priKey1 << std::endl;
    std::cout << "  publicKeyHex-1  ::: " << pubKey1 << std::endl;
    std::cout << "  privateKeyHex-2 ::: " << priKey2 << std::endl;
    std::cout << "  publicKeyHex-2  ::: " << pubKey2 << std::endl;
    std::cout << std::endl;

    // ==================== 2. 加密并签名 → 验签并解密 ====================
    std::cout << ">>> 2. 加密并签名 → 验签并解密（先加密再签名，先验签再解密）" << std::endl;

    auto pair = SM2Util::encryptSign(originalContent, pubKey1, priKey2);
    std::cout << "  CipherText ::: " << pair.ciphertext.substr(0, 150) << "..." << std::endl;
    std::cout << "  Signature  ::: " << pair.signature << std::endl;
    std::cout << std::endl;

    std::string verifyDecrypt = SM2Util::verifyDecrypt(
        pair.ciphertext, pair.signature, pubKey2, priKey1);
    std::cout << "  VerifyDecrypt ::: " << verifyDecrypt << std::endl;
    std::cout << "  WhetherVerifyDecryptEqualsOriginalContent ::: "
              << (originalContent == verifyDecrypt ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 3. 仅加密/解密 ====================
    std::cout << ">>> 3. 公钥加密 → 私钥解密" << std::endl;

    std::string encryptedContent = SM2Util::encryptToHex(originalContent, pubKey1);
    std::cout << "  EncryptedContent ::: " << encryptedContent.substr(0, 150) << "..." << std::endl;

    std::string decryptedContent = SM2Util::decrypt(encryptedContent, priKey1);
    std::cout << "  DecryptedContent ::: " << decryptedContent << std::endl;
    std::cout << "  WhetherDecryptEqualsOriginalContent ::: "
              << (originalContent == decryptedContent ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 4. 签名/验签 ====================
    std::cout << ">>> 4. 私钥签名 → 公钥验签" << std::endl;

    std::string contentSignature = SM2Util::signToHex(originalContent, priKey2);
    std::cout << "  ContentSignature ::: " << contentSignature << std::endl;

    bool verify = SM2Util::verify(originalContent, pubKey2, contentSignature);
    std::cout << "  WhetherVerifyEqualsOriginalContent ::: "
              << (verify ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 5. Base64 格式示例 ====================
    std::cout << ">>> 5. Base64 格式输出（可选）" << std::endl;

    std::string encryptedB64 = SM2Util::encryptToBase64(originalContent, pubKey1);
    std::cout << "  Encrypted (Base64) ::: " << encryptedB64.substr(0, 100) << "..." << std::endl;

    std::string signatureB64 = SM2Util::signToBase64(originalContent, priKey2);
    std::cout << "  Signature  (Base64) ::: " << signatureB64 << std::endl;
    std::cout << std::endl;

    std::cout << "=== SM2 Sample 完成 ===" << std::endl;
    return 0;
}
