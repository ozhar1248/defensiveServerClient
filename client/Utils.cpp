#include "Utils.h"
#include <iostream>
#include <iomanip>
#include <algorithm>

std::string toHex32(const std::array<uint8_t,16>& id) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (uint8_t b : id) {
        s.push_back(H[(b >> 4) & 0xF]);
        s.push_back(H[b & 0xF]);
    }
    return s;
}

void dumpHexPrefix(const std::vector<uint8_t>& v, size_t n) {
    const size_t count = std::min(n, v.size());
    std::ios old_state(nullptr);
    old_state.copyfmt(std::cout);

    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < count; ++i) {
        if (i) std::cout << ' ';
        std::cout << std::setw(2) << static_cast<unsigned>(v[i]);
    }
    std::cout << std::dec;
    std::cout.copyfmt(old_state);
}
