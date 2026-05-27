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
     * SM4 GCM 加密，返回 Base64(IV[12] + 密文 + Tag[16])
     */
    static std::string encryptGcm(const std::vector<unsigned char>& key, const std::vector<unsigned char>& input);

    /**
     * SM4 GCM 解密，输入 Base64(IV[12] + 密文 + Tag[16])
     */
    static std::vector<unsigned char> decryptGcm(const std::vector<unsigned char>& key, const std::string& ciphertextBase64);

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
