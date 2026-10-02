/**
 * SM3 国密哈希算法示例
 *
 * 快速上手：
 * 1. cd cpp/crossmool/build && cmake --build .
 * 2. 运行：./bin/sm3_sample
 *
 * 核心能力：
 * - SM3 消息摘要（256-bit，类似 SHA-256）
 * - HMAC-SM3 消息认证码（防篡改 + 防伪造）
 * - 支持 Hex / Base64 输出
 * - 支持字符串和字节数组输入
 */

#include <iostream>
#include <string>
#include <vector>
#include "SM3Util.h"

int main()
{
    std::cout << "============================================================" << std::endl;
    std::cout << "  SM3 Sample — 国密哈希算法 (256-bit)" << std::endl;
    std::cout << "============================================================" << std::endl;
    std::cout << std::endl;

    // ==================== 1. SM3 消息摘要 ====================
    std::cout << ">>> 1. SM3 消息摘要 (Digest)" << std::endl;

    std::string input =
        "在这个全球化时代，無論身處何地，"
        "learning and growth are always the keys to a fulfilling life.";

    std::cout << "  Input        ::: " << input << std::endl;

    std::string hash = SM3Util::digestToStr(input, "UTF-8", false);
    std::cout << "  SM3 Hash     ::: " << hash << std::endl;

    // 显式指定 Hex 输出（与默认行为一致）
    std::string hashHex = SM3Util::digestToStr(input, "UTF-8", false);
    std::cout << "  SM3 Hash (Hex) ::: " << hashHex << std::endl;

    bool equals = hash == hashHex;
    std::cout << "  Whether Hash Equals Hex ::: " << (equals ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 2. HMAC-SM3 消息认证码 ====================
    std::cout << ">>> 2. HMAC-SM3 消息认证码" << std::endl;

    // 生成 HMAC 密钥（32 字节 = 256-bit）
    std::string hmacKey = SM3Util::generateHmacKeyToStr(32, false);
    std::cout << "  HMAC Key      ::: " << hmacKey << std::endl;

    // 计算 HMAC（Hex 输出）
    std::string hmacValue = SM3Util::hmacToStr(input, hmacKey, false);
    std::cout << "  HMAC Value    ::: " << hmacValue << std::endl;

    // 相同密钥 + 相同输入 → 相同输出（确定性）
    std::string hmacValue2 = SM3Util::hmacToStr(input, hmacKey, false);
    std::cout << "  HMAC Value 2  ::: " << hmacValue2 << std::endl;

    bool hmacEquals = hmacValue == hmacValue2;
    std::cout << "  Whether HMAC Values Equal ::: " << (hmacEquals ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 3. HMAC 校验 ====================
    std::cout << ">>> 3. HMAC 校验（防篡改验证）" << std::endl;

    bool hmacVerified = SM3Util::hmacVerify(input, hmacKey, hmacValue);
    std::cout << "  HMAC Verify (correct)   ::: " << (hmacVerified ? "true" : "false") << std::endl;

    // 篡改消息后校验失败
    bool hmacTampered = SM3Util::hmacVerify(input + "X", hmacKey, hmacValue);
    std::cout << "  HMAC Verify (tampered)  ::: " << (hmacTampered ? "true" : "false") << std::endl;
    std::cout << std::endl;

    // ==================== 4. 字节数组输入 ====================
    std::cout << ">>> 4. 字节数组摘要（非字符串场景）" << std::endl;

    std::vector<unsigned char> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto rawDigest = SM3Util::digest(data);

    std::cout << "  Input (5 bytes): ";
    for (auto b : data)
        std::cout << std::hex << static_cast<int>(b) << " ";
    std::cout << std::endl;

    std::cout << "  Digest (HEX)  : " << SM3Util::digestToHex(data) << std::endl;
    std::cout << "  Digest length  : " << rawDigest.size() << " bytes" << std::endl;
    std::cout << std::endl;

    // ==================== 5. Base64 输出示例 ====================
    std::cout << ">>> 5. Base64 格式输出（可选）" << std::endl;

    std::string hashB64 = SM3Util::digestToStr(input, "UTF-8", true);
    std::cout << "  SM3 Hash (Base64) ::: " << hashB64 << std::endl;

    std::string hmacKeyB64 = SM3Util::generateHmacKeyToStr(32, true);
    std::cout << "  HMAC Key (Base64) ::: " << hmacKeyB64 << std::endl;
    std::cout << std::endl;

    std::cout << "=== SM3 Sample 完成 ===" << std::endl;
    return 0;
}
