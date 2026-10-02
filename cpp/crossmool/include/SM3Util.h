#ifndef SM3UTIL_H
#define SM3UTIL_H

#include "crossmool_config.h"
#include <string>
#include <vector>

class CROSSMOOL_API SM3Util {
public:
    /**
     * Generate SM3 hash for byte array
     */
    static std::vector<unsigned char> digest(const std::vector<unsigned char>& input);

    /**
     * Generate SM3 hash for byte array and return as hex string
     */
    static std::string digestToHex(const std::vector<unsigned char>& input);

    /**
     * Generate SM3 hash for byte array and return as hex or base64 string
     */
    static std::string digestToStr(const std::vector<unsigned char>& input, bool toBase64 = false);

    /**
     * Generate SM3 hash for string with specified charset and return as hex or base64 string
     */
    static std::string digestToStr(const std::string& input, const std::string& charset = "UTF-8", bool toBase64 = false);

    /**
     * Generate SM3 hash for string with UTF-8 charset and return as hex string (default)
     */
    static std::string digestToStr(const std::string& input);

    /**
     * Generate random key for HMAC-SM3 with specified length
     */
    static std::vector<unsigned char> generateHmacKey(int keyLengthInBytes = 32);

    /**
     * Generate random key for HMAC-SM3 and return as hex or base64 string
     */
    static std::string generateHmacKeyToStr(int keyLengthInBytes = 32, bool toBase64 = false);

    /**
     * Perform HMAC-SM3 operation
     */
    static std::vector<unsigned char> hmac(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key);

    /**
     * Perform HMAC-SM3 operation with string parameters
     */
    static std::vector<unsigned char> hmac(const std::string& data, const std::string& key);

    /**
     * Perform HMAC-SM3 operation and return as hex or base64 string
     */
    static std::string hmacToStr(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, bool toBase64 = false);

    /**
     * Perform HMAC-SM3 operation with string parameters and return as hex or base64 string
     */
    static std::string hmacToStr(const std::string& data, const std::string& key, bool toBase64 = false);

    /**
     * Verify HMAC-SM3 signature
     */
    static bool hmacVerify(const std::string& data, const std::string& key, const std::string& receivedHmac);
};

#endif // SM3UTIL_H