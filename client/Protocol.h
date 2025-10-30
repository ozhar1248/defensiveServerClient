#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <array>

//
// ============================================================================
//  Protocol.h
//  --------------------------------------------------------------------------
//  Defines all constants, data structures, and helper methods used for
//  constructing and parsing messages exchanged between the client and server.
//
//  Each message typically follows this binary layout:
//
//      [Header]
//        - Version (1 byte)
//        - Code (2 bytes, little-endian)
//        - Payload size (4 bytes, little-endian)
//
//      [Payload]
//        - Message content, structure depends on the message code.
//
//  This header defines both request and response codes, message formats,
//  and helper utilities for serializing/deserializing protocol data.
// ============================================================================
//

// ---------------------------------------------------------------------------
// Version and protocol codes
// ---------------------------------------------------------------------------
constexpr uint8_t CLIENT_VERSION = 1;          // Current client protocol version
constexpr uint8_t SERVER_VERSION_EXPECTED = 2; // Expected server protocol version

// Registration
constexpr uint16_t CODE_REGISTRATION_REQ = 600;
constexpr uint16_t CODE_REGISTRATION_OK = 2100;
constexpr uint16_t CODE_ERROR = 9000;

// Client list retrieval
constexpr uint16_t CODE_CLIENTS_LIST_REQ = 601;
constexpr uint16_t CODE_CLIENTS_LIST_OK = 2101;

// Public key exchange
constexpr uint16_t CODE_PUBLIC_KEY_REQ = 602;
constexpr uint16_t CODE_PUBLIC_KEY_OK = 2102;

// Messaging
constexpr uint16_t CODE_SEND_MESSAGE_REQ = 603;
constexpr uint16_t CODE_SEND_MESSAGE_OK = 2103;

// Waiting messages (message inbox)
constexpr uint16_t CODE_PULL_WAITING_REQ = 604;
constexpr uint16_t CODE_PULL_WAITING_OK = 2104;

// ---------------------------------------------------------------------------
// Data size definitions
// ---------------------------------------------------------------------------
constexpr size_t CLIENT_ID_LEN = 16; // UUID length in bytes
constexpr size_t REG_NAME_LEN = 255; // Max username length in registration
constexpr size_t REG_PUB_LEN = 400;  // Base64-encoded RSA public key length // couldn't make it with 160

constexpr size_t ENTRY_UUID_LEN = 16;  // UUID in clients list entries
constexpr size_t ENTRY_NAME_LEN = 255; // Username field in clients list entries
constexpr size_t ENTRY_TOTAL = ENTRY_UUID_LEN + ENTRY_NAME_LEN;

constexpr size_t RESP_PUBKEY_LEN = 400; // couldn't make it with 160 because it created bugs
constexpr size_t SEND_ACK_LEN = 20;     // ACK payload size for SEND_MESSAGE_OK

// ---------------------------------------------------------------------------
// Serialization helpers (little-endian encoding)
// ---------------------------------------------------------------------------
inline void append_u16_le(std::vector<uint8_t> &v, uint16_t x)
{
    v.push_back(uint8_t(x & 0xFF));
    v.push_back(uint8_t((x >> 8) & 0xFF));
}

inline void append_u32_le(std::vector<uint8_t> &v, uint32_t x)
{
    v.push_back(uint8_t(x & 0xFF));
    v.push_back(uint8_t((x >> 8) & 0xFF));
    v.push_back(uint8_t((x >> 16) & 0xFF));
    v.push_back(uint8_t((x >> 24) & 0xFF));
}

// ---------------------------------------------------------------------------
// Basic protocol data structures
// ---------------------------------------------------------------------------

// Represents a parsed reply from the server.
struct ServerReply
{
    uint8_t version{};            // Server protocol version
    uint16_t code{};              // Reply code (e.g., 2100 for OK)
    uint32_t payloadSize{};       // Payload length in bytes
    std::vector<uint8_t> payload; // Raw payload data (optional)
};

// 16-byte universally unique client ID
using Uuid = std::array<uint8_t, 16>;

// Represents an entry in the clients list (username + UUID)
struct ClientEntry
{
    Uuid id;
    std::string name; // ASCII username (padded with NULs)
};

// Represents a single pending message from another client
struct WaitingMessage
{
    Uuid fromId;                  // Sender’s client ID
    uint32_t msgId;               // Unique message ID (server-assigned)
    uint8_t type;                 // 1=req sym key, 2=sym key, 3=text message
    std::vector<uint8_t> content; // Encrypted message content
};

// ---------------------------------------------------------------------------
// Protocol utility class
// ---------------------------------------------------------------------------
class Protocol
{
public:
    // Builds a registration request message.
    static std::vector<uint8_t> buildRegistration(
        const std::array<uint8_t, 16> &clientId,
        const std::string &usernameAscii,
        const std::string &publicKeyAscii);

    // Builds a request for the full clients list.
    static std::vector<uint8_t> buildClientsListReq(
        const std::array<uint8_t, 16> &clientId);

    // Builds a request for another client’s public key.
    // Payload contains target clientId (16 bytes).
    static std::vector<uint8_t> buildPublicKeyReq(
        const std::array<uint8_t, 16> &myClientIdHeader,
        const std::array<uint8_t, 16> &targetClientIdPayload);

    // Parses the 7-byte reply header from the server.
    static ServerReply parseServerReplyHeader(const uint8_t *header7);

    // Builds a message-sending request (text, symmetric key, etc.).
    static std::vector<uint8_t> buildSendMessageReq(
        const std::array<uint8_t, 16> &myClientIdHeader,
        const std::array<uint8_t, 16> &destClientId,
        uint8_t messageType,
        const std::vector<uint8_t> &content);

    // Builds a request to pull waiting messages from the server.
    static std::vector<uint8_t> buildPullWaitingReq(
        const std::array<uint8_t, 16> &myClientIdHeader);

    // Parses a clients-list payload into structured entries.
    static std::vector<ClientEntry> parseClientsListPayload(
        const std::vector<uint8_t> &payload);

    // Parses a waiting-messages payload into structured message objects.
    static std::vector<WaitingMessage> parseWaitingMessagesPayload(
        const std::vector<uint8_t> &payload);

    // Checks if a reply has the expected success code.
    static bool isOk(const ServerReply &r, uint16_t expectedCode);

    // Checks if the server reply is an ACK for a sent message.
    static bool isSendAck(const ServerReply &r);
};
