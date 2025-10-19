#pragma once
#include <string>
#include <utility>
#include <array>

class FileConfig {
public:
    static std::pair<std::string, unsigned short> readServerInfo();

    // NEW: read me.info => {username, 16-byte clientId}
    static std::pair<std::string, std::array<uint8_t,16>> readMeInfo();
};
