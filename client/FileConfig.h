// FileConfig.h
#pragma once
#include <string>
#include <utility>
#include <tuple>
#include <array>
#include <cstdint>

class FileConfig {
public:
    static std::pair<std::string, unsigned short> readServerInfo();

    // // Reads username, client ID, and Base64-encoded private key from my.info
    static std::tuple<std::string, std::array<std::uint8_t,16>, std::string> readFullMyInfo();

    static void writeMyInfo(const std::string& username,
                            const std::array<std::uint8_t,16>& clientId,
                            const std::string& privateKeyBase64);

    static std::string generateAndSavePrivateKey(const std::string& username,
                                                 const std::array<std::uint8_t,16>& clientId);
};
