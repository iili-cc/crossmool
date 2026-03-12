#include "Base64Util.h"
#include <string>
#include <vector>

static const std::string CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string Base64Util::encodeBase64Str(const std::vector<unsigned char>& bytes) {
    std::string result;
    int val = 0, valb = -6;

    for (unsigned char c : bytes) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(CHARACTERS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        result.push_back(CHARACTERS[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (result.size() % 4) {
        result.push_back('=');
    }
    return result;
}

std::vector<unsigned char> Base64Util::decodeBase64Str(const std::string& base64) {
    static int pos[256];
    for (int i = 0; i < 256; ++i) pos[i] = -1;
    for (int i = 0; i < 64; ++i) pos[CHARACTERS[i]] = i;

    std::vector<unsigned char> result;
    int val = 0, valb = -8;
    for (char c : base64) {
        if (pos[static_cast<unsigned char>(c)] == -1) break;
        val = (val << 6) + pos[static_cast<unsigned char>(c)];
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<unsigned char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return result;
}

bool Base64Util::isBase64String(const std::string& str) {
    if (str.empty()) return false;

    // Check if length is multiple of 4
    if (str.length() % 4 != 0) return false;

    // Check valid characters and padding
    for (size_t i = 0; i < str.length(); ++i) {
        char c = str[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/') {
            continue;
        } else if (c == '=') {
            // Padding must only appear at the end
            if (i < str.length() - 2 || (i == str.length() - 2 && str[i+1] != '=')) {
                return false;
            }
        } else {
            return false;
        }
    }

    return true;
}