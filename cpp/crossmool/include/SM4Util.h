#ifndef SM4UTIL_H
#define SM4UTIL_H

#include <string>
#include <vector>

class SM4Util {
public:
    /**
     * Generate random 128-bit (16 bytes) SM4 key
     */
    static std::vector<unsigned char> generateKey();

    /**
     * Generate random SM4 key and return as hex string
     */
    static std::string generateKeyAsHex();

    /**
     * Parse hex string to SM4 key byte array
     */
    static std::vector<unsigned char> parseHexKey(const std::string& hexKey);

    /**
     * Encrypt using ECB mode with native implementation, return as hex string
     */
    static std::string encryptEcbNative(const std::vector<unsigned char>& key, const std::vector<unsigned char>& input);

    /**
     * Decrypt using ECB mode with native implementation
     */
    static std::string decryptEcbNative(const std::vector<unsigned char>& key, const std::string& hexCipherText);

    /**
     * Encrypt using ECB mode with JCA-equivalent implementation, return as hex string
     */
    static std::string encryptEcbJca(const std::vector<unsigned char>& key, const std::string& plainText);

    /**
     * Decrypt using ECB mode with JCA-equivalent implementation
     */
    static std::string decryptEcbJca(const std::vector<unsigned char>& key, const std::string& hexCipherText);
};

#endif // SM4UTIL_H