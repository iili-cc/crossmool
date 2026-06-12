#ifndef SM4UTIL_H
#define SM4UTIL_H

#include <string>
#include <vector>

class SM4Util {
public:
    static std::vector<unsigned char> generateKey();

    static std::string generateKeyAsHex();

    static std::vector<unsigned char> parseHexKey(const std::string& hexKey);

    /**
     * SM4 GCM 加密，返回 Hex(IV[12] + 密文 + Tag[16]) 默认，toBase64=true 返回 Base64
     */
    static std::string encryptGcm(const std::vector<unsigned char>& key, const std::vector<unsigned char>& input, bool toBase64 = false);

    /**
     * SM4 GCM 解密，输入自动检测 Hex 或 Base64 格式
     */
    static std::vector<unsigned char> decryptGcm(const std::vector<unsigned char>& key, const std::string& ciphertextEncoded);

    /**
     * SM4 GCM 加密（字符串输入），返回 Base64(IV[12] + 密文 + Tag[16])
     */
    static std::string encryptGcmString(const std::vector<unsigned char>& key, const std::string& plainText);

    /**
     * SM4 GCM 解密返回字符串
     */
    static std::string decryptGcmToString(const std::vector<unsigned char>& key, const std::string& ciphertextBase64);
};

#endif // SM4UTIL_H
