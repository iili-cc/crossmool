#ifndef STRINGUTIL_H
#define STRINGUTIL_H

#include <string>
#include <vector>
#include <memory>

class StringUtil {
public:
    /**
     * Convert string to byte vector using specified charset
     */
    static std::vector<unsigned char> stringToBytes(const std::string& str, const std::string& charset = "UTF-8");

    /**
     * Convert byte vector to string using specified charset
     */
    static std::string bytesToString(const std::vector<unsigned char>& bytes, const std::string& charset = "UTF-8");

    /**
     * Check if string is hex format
     */
    static bool isHexString(const std::string& str);

    /**
     * Check if string is base64 format
     */
    static bool isBase64String(const std::string& str);
};

#endif // STRINGUTIL_H