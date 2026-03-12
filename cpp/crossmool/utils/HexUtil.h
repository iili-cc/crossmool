#ifndef HEXUTIL_H
#define HEXUTIL_H

#include <string>
#include <vector>

class HexUtil {
public:
    /**
     * Encode byte array to hex string
     */
    static std::string encodeHexStr(const std::vector<unsigned char>& bytes);

    /**
     * Decode hex string to byte array
     */
    static std::vector<unsigned char> decodeHexStr(const std::string& hex);

    /**
     * Check if string is valid hex format
     */
    static bool isHexString(const std::string& str);
};

#endif // HEXUTIL_H