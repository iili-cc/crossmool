#ifndef BASE64UTIL_H
#define BASE64UTIL_H

#include "../include/crossmool_config.h"
#include <string>
#include <vector>

class CROSSMOOL_API Base64Util {
public:
    /**
     * Encode byte array to base64 string
     */
    static std::string encodeBase64Str(const std::vector<unsigned char>& bytes);

    /**
     * Decode base64 string to byte array
     */
    static std::vector<unsigned char> decodeBase64Str(const std::string& base64);

    /**
     * Check if string is valid base64 format
     */
    static bool isBase64String(const std::string& str);
};

#endif // BASE64UTIL_H