// FileConfig.h
#pragma once
#include <string>
#include <utility>

class FileConfig {
public:
    // Reads "server.info" located next to the executable.
    // Returns {ip, port}.
    static std::pair<std::string, unsigned short> readServerInfo();
};
