/**
 * SM4 国密对称加密算法示例（GCM 模式）
 *
 * 快速上手：
 * 1. cd cpp/crossmool/build && cmake --build .
 * 2. 运行：./bin/sm4_sample
 *
 * 核心能力：
 * - 生成 SM4 密钥（128-bit，Hex / Base64 格式）
 * - SM4-GCM 加密（带认证标签，防篡改）
 * - SM4-GCM 解密（自动检测 Hex / Base64 输入）
 * - GCM 模式：任何篡改都会导致解密失败
 */

#include <iostream>
#include <string>
#include <vector>
#include "SM4Util.h"

int main()
{
    std::cout << "============================================================" << std::endl;
    std::cout << "  SM4 Sample — 国密对称加密 (GCM 模式)" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;

    // ==================== 原始内容 ====================
    std::string originalContent =
        "今天天气真好，气温大约 28°C，我决定出門走走（出門走走）。"
        "路过咖啡店时買了一杯美式，順便（顺便）看了下手机，"
        "今日步數（步数）已经 12,345 步了，距離目標還差 3,000 步左右。"
        "朋友发来一条消息说：\"Don't forget to bring your umbrella, just in case!\" "
        "我回了个笑脸，心想應該不會下雨吧。生活嘛，簡單點就好，快樂其實很簡單。";

    std::cout << "OriginalContent ::: " << originalContent << std::endl;
    std::cout << std::endl;

    // ==================== 1. 生成 SM4 密钥 ====================
    std::cout << ">>> 1. 生成 SM4 密钥（128-bit）" << std::endl;

    std::string hexKey = SM4Util::generateKeyAsHex();
    std::cout << "  SM4 Hex Key    ::: " << hexKey << std::endl;

    std::string base64Key = SM4Util::generateKeyAsBase64();
    std::cout << "  SM4 Base64 Key ::: " << base64Key << std::endl;
    std::cout << std::endl;

    // 解析密钥为字节数组
    auto keyBytes = SM4Util::parseHexKey(hexKey);

    // ==================== 2. Hex 密钥 GCM 加解密 ====================
    std::cout << ">>> 2. 使用 Hex 密钥进行 GCM 加解密" << std::endl;

    std::vector<unsigned char> vPlain(originalContent.begin(), originalContent.end());
    std::string encryptedHex = SM4Util::encryptGcm(keyBytes, vPlain, false);
    std::cout << "  Encrypted (Hex) ::: " << encryptedHex.substr(0, 150) << "..." << std::endl;

    std::string decryptedHex = SM4Util::decryptGcmToString(keyBytes, encryptedHex);
    std::cout << "  Decrypted (Hex) ::: " << decryptedHex << std::endl;
    std::cout << "  WhetherDecryptEqualsOriginalContent (Hex) ::: "
              << (originalContent == decryptedHex ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 3. Base64 密钥 GCM 加解密 ====================
    std::cout << ">>> 3. 使用 Base64 输出进行 GCM 加解密" << std::endl;

    std::string encryptedB64 = SM4Util::encryptGcm(keyBytes, vPlain, true);
    std::cout << "  Encrypted (Base64) ::: " << encryptedB64.substr(0, 100) << "..." << std::endl;

    auto decryptedB64 = SM4Util::decryptGcm(keyBytes, encryptedB64);
    std::string decryptedB64Str(decryptedB64.begin(), decryptedB64.end());
    std::cout << "  Decrypted (Base64) ::: " << decryptedB64Str << std::endl;
    std::cout << "  WhetherDecryptEqualsOriginalContent (Base64) ::: "
              << (originalContent == decryptedB64Str ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 4. 随机 IV（每次加密结果不同） ====================
    std::cout << ">>> 4. 随机 IV 验证（每次 GCM 加密密文不同）" << std::endl;

    std::string ct1 = SM4Util::encryptGcmString(keyBytes, "Same plaintext");
    std::string ct2 = SM4Util::encryptGcmString(keyBytes, "Same plaintext");
    std::cout << "  Ciphertext 1 ::: " << ct1.substr(0, 50) << "..." << std::endl;
    std::cout << "  Ciphertext 2 ::: " << ct2.substr(0, 50) << "..." << std::endl;
    std::cout << "  IV differs (ciphertexts not equal) ::: "
              << (ct1 != ct2 ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 5. GCM 防篡改验证 ====================
    std::cout << ">>> 5. GCM 防篡改验证" << std::endl;
    std::cout << "  （故意篡改密文末尾字符，GCM 应检测到并拒绝解密）" << std::endl;

    std::string tampered = encryptedHex;
    tampered[tampered.length() - 2] = 'X';
    tampered[tampered.length() - 1] = 'X';

    try {
        std::string hacked = SM4Util::decryptGcmToString(keyBytes, tampered);
        std::cout << "  Tampered decrypted ::: " << hacked << std::endl;
    } catch (const std::exception &ex) {
        std::cout << "  GCM detected tampering, decryption failed ::: " << ex.what() << std::endl;
    }
    std::cout << std::endl;

    // ==================== 6. Base64 输出示例 ====================
    std::cout << ">>> 6. Base64 格式输出（可选）" << std::endl;

    std::string ctB64Str = SM4Util::encryptGcmString(keyBytes, originalContent);
    std::cout << "  Encrypted String (Base64) ::: " << ctB64Str.substr(0, 100) << "..." << std::endl;
    std::cout << std::endl;

    std::cout << "=== SM4 Sample 完成 ===" << std::endl;
    return 0;
}
