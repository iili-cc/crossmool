#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "SM2Util.h"
#include "SM4Util.h"
#include "HexUtil.h"
int main() {
    std::string j, l;
    while (std::getline(std::cin, l)) j += l;
    auto g = [&](const std::string& k) -> std::string {
        std::string s = "\"" + k + "\":\"";
        auto p = j.find(s);
        if (p == std::string::npos) { s = "\"" + k + "\": \""; p = j.find(s); }
        if (p == std::string::npos) return "";
        p += s.length();
        auto e = j.find("\"", p);
        if (e == std::string::npos) return "";
        std::string r = j.substr(p, e - p);
        std::string o;
        bool esc = false;
        for (char c : r) { if (esc) { o += c; esc = false; } else if (c == '\\') { esc = true; } else { o += c; } }
        return o;
    };
    std::string cs = g("x_enc"), ss = g("x_sig"), sc = g("x_sm4");
    std::cout << "{";
    bool f = true;
    const char* MSG = "Hello, \xe8\xbf\x99\xe6\x98\xaf\xe8\xb7\xa8\xe8\xaf\xad\xe8\xa8\x80\xe5\x9b\xbd\xe5\xaf\x86\xe4\xba\x92\xe9\x80\x9a\xe6\x80\xa7\xe6\xb5\x8b\xe8\xaf\x95\xe6\x95\xb0\xe6\x8d\xae";
    if (!cs.empty()) {
        try {
            std::string d = SM2Util::decrypt(cs, "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03");
            if (f) f = false; else std::cout << ",";
            std::cout << "\"enc\":\"" << (d == MSG ? "PASS" : "FAIL") << "\"";
        } catch (...) { if (f) f = false; else std::cout << ","; std::cout << "\"enc\":\"FAIL\""; }
    }
    if (!ss.empty()) {
        try {
            bool ok = SM2Util::verify(std::string(MSG), "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", ss);
            if (f) f = false; else std::cout << ",";
            std::cout << "\"sig\":\"" << (ok ? "PASS" : "FAIL") << "\"";
        } catch (...) { if (f) f = false; else std::cout << ","; std::cout << "\"sig\":\"FAIL\""; }
    }
    if (!sc.empty()) {
        try {
            auto sk = HexUtil::decodeHexStr("0123456789abcdeffedcba9876543210");
            auto d = SM4Util::decryptGcm(sk, sc);
            std::string ds(d.begin(), d.end());
            if (f) f = false; else std::cout << ",";
            std::cout << "\"sm4\":\"" << (ds == MSG ? "PASS" : "FAIL") << "\"";
        } catch (...) { if (f) f = false; else std::cout << ","; std::cout << "\"sm4\":\"FAIL\""; }
    }
    if (!cs.empty() && !ss.empty()) {
        try {
            std::string d2 = SM2Util::decrypt(cs, "b273ef43c6866dd2c8b8a0303748e45dd135573ddb001a47141ff8f20f2a9b03");
            bool ok2 = SM2Util::verify(d2, "3059301306072a8648ce3d020106082a811ccf5501822d03420004192c000fadd3d2d40be8d4734b91bbfe1316f439077014ffd85959e02daeec3ccbec8c3786dbc431aab82e636a09e0bf752e760fd34e512aba94c5203d617226", ss);
            if (f) f = false; else std::cout << ",";
            std::cout << "\"esvd\":\"" << (d2 == MSG && ok2 ? "PASS" : "FAIL") << "\"";
        } catch (...) { if (f) f = false; else std::cout << ","; std::cout << "\"esvd\":\"FAIL\""; }
    }
    std::cout << "}" << std::endl;
    return 0;
}
