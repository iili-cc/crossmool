#include "StringUtil.h"
#include <locale>
#include <codecvt>
#include <algorithm>
#include "Base64Util.h"
#include "HexUtil.h"

std::vector<unsigned char> StringUtil::stringToBytes(const std::string& str, const std::string& charset) {
    // For UTF-8, we can directly convert to bytes
    if (charset == "UTF-8" || charset == "utf-8") {
        std::vector<unsigned char> result(str.begin(), str.end());
        return result;
    } else {
        // For other charsets, we might need more complex conversion
        // For now, treat as UTF-8 for compatibility
        std::vector<unsigned char> result(str.begin(), str.end());
        return result;
    }
}

std::string StringUtil::bytesToString(const std::vector<unsigned char>& bytes, const std::string& charset) {
    // For UTF-8, we can directly convert from bytes
    if (charset == "UTF-8" || charset == "utf-8") {
        std::string result(bytes.begin(), bytes.end());
        return result;
    } else {
        // For other charsets, we might need more complex conversion
        // For now, treat as UTF-8 for compatibility
        std::string result(bytes.begin(), bytes.end());
        return result;
    }
}

bool StringUtil::isHexString(const std::string& str) {
    return HexUtil::isHexString(str);
}

bool StringUtil::isBase64String(const std::string& str) {
    return Base64Util::isBase64String(str);
}