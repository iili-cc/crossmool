#include "HexUtil.h"
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>

std::string HexUtil::encodeHexStr(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<unsigned char> HexUtil::decodeHexStr(const std::string& hex) {
    std::vector<unsigned char> result;
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        unsigned int byteValue;
        if (!(std::istringstream(byteStr) >> std::hex >> byteValue)) {
            throw std::invalid_argument("Invalid hex character");
        }
        result.push_back(static_cast<unsigned char>(byteValue));
    }
    return result;
}

bool HexUtil::isHexString(const std::string& str) {
    if (str.empty() || str.length() % 2 != 0) {
        return false;
    }

    for (char c : str) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }
    return true;
}