#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>

constexpr uint8_t  CLIENT_VERSION = 1;
constexpr uint8_t  SERVER_VERSION_EXPECTED = 2;

constexpr uint16_t CODE_REGISTRATION_REQ = 600;
constexpr uint16_t CODE_REGISTRATION_OK  = 2100;
constexpr uint16_t CODE_ERROR            = 9000;

// NEW:
constexpr uint16_t CODE_CLIENTS_LIST_REQ = 601;
constexpr uint16_t CODE_CLIENTS_LIST_OK  = 2101;

constexpr size_t CLIENT_ID_LEN = 16;
constexpr size_t REG_NAME_LEN  = 255;
constexpr size_t REG_PUB_LEN   = 150;

constexpr size_t ENTRY_UUID_LEN = 16;
constexpr size_t ENTRY_NAME_LEN = 255;
constexpr size_t ENTRY_TOTAL    = ENTRY_UUID_LEN + ENTRY_NAME_LEN; // 271

inline void append_u16_le(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(uint8_t(x & 0xFF));
    v.push_back(uint8_t((x >> 8) & 0xFF));
}
inline void append_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t(x & 0xFF));
    v.push_back(uint8_t((x >> 8) & 0xFF));
    v.push_back(uint8_t((x >> 16) & 0xFF));
    v.push_back(uint8_t((x >> 24) & 0xFF));
}

struct ServerReply {
    uint8_t  version{};
    uint16_t code{};
    uint32_t payloadSize{};
    std::vector<uint8_t> payload;
};

class Protocol {
public:
    static std::vector<uint8_t> buildRegistration(
        const std::array<uint8_t, 16>& clientId,
        const std::string& usernameAscii,
        const std::string& publicKeyAscii);

    // NEW: list clients request (no payload; uses clientId in header)
    static std::vector<uint8_t> buildClientsListReq(
        const std::array<uint8_t, 16>& clientId);

    static ServerReply parseServerReplyHeader(const uint8_t* header7);
};
