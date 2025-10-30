#include "Protocol.h"
#include <algorithm>

std::vector<uint8_t> Protocol::buildRegistration(
    const std::array<uint8_t,16>& clientId,
    const std::string& usernameAscii,
    const std::string& publicKeyAscii)
{
    std::vector<uint8_t> payload; payload.resize(REG_NAME_LEN + REG_PUB_LEN, 0);
    size_t nlen = std::min(usernameAscii.size(), REG_NAME_LEN);
    std::copy_n(reinterpret_cast<const uint8_t*>(usernameAscii.data()), nlen, payload.data());
    size_t klen = std::min(publicKeyAscii.size(), REG_PUB_LEN);
    std::copy_n(reinterpret_cast<const uint8_t*>(publicKeyAscii.data()), klen, payload.data() + REG_NAME_LEN);

    std::vector<uint8_t> msg;
    msg.reserve(16 + 1 + 2 + 4 + payload.size());
    msg.insert(msg.end(), clientId.begin(), clientId.end());
    msg.push_back(CLIENT_VERSION);
    append_u16_le(msg, CODE_REGISTRATION_REQ);
    append_u32_le(msg, static_cast<uint32_t>(payload.size()));
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}

std::vector<uint8_t> Protocol::buildClientsListReq(
    const std::array<uint8_t,16>& clientId)
{
    std::vector<uint8_t> msg;
    msg.reserve(16 + 1 + 2 + 4);
    msg.insert(msg.end(), clientId.begin(), clientId.end());
    msg.push_back(CLIENT_VERSION);
    append_u16_le(msg, CODE_CLIENTS_LIST_REQ);
    append_u32_le(msg, 0); // no payload
    return msg;
}

std::vector<uint8_t> Protocol::buildPublicKeyReq(
    const std::array<uint8_t,16>& myClientIdHeader,
    const std::array<uint8_t,16>& targetClientIdPayload)
{
    std::vector<uint8_t> msg;
    msg.reserve(16 + 1 + 2 + 4 + 16);
    // header
    msg.insert(msg.end(), myClientIdHeader.begin(), myClientIdHeader.end());
    msg.push_back(CLIENT_VERSION);
    append_u16_le(msg, CODE_PUBLIC_KEY_REQ);
    append_u32_le(msg, 16);
    // payload = target client id (16 bytes)
    msg.insert(msg.end(), targetClientIdPayload.begin(), targetClientIdPayload.end());
    return msg;
}

ServerReply Protocol::parseServerReplyHeader(const uint8_t* h) {
    ServerReply r;
    r.version = h[0];
    r.code = static_cast<uint16_t>(h[1] | (h[2] << 8));
    r.payloadSize = static_cast<uint32_t>(h[3] | (h[4] << 8) | (h[5] << 16) | (h[6] << 24));
    return r;
}

std::vector<uint8_t> Protocol::buildSendMessageReq(
    const std::array<uint8_t,16>& myClientIdHeader,
    const std::array<uint8_t,16>& destClientId,
    uint8_t messageType,
    const std::vector<uint8_t>& content)
{
    std::vector<uint8_t> payload;
    payload.reserve(16 + 1 + 4 + content.size());
    payload.insert(payload.end(), destClientId.begin(), destClientId.end());
    payload.push_back(messageType);
    append_u32_le(payload, static_cast<uint32_t>(content.size()));
    payload.insert(payload.end(), content.begin(), content.end());

    std::vector<uint8_t> msg;
    msg.reserve(16 + 1 + 2 + 4 + payload.size());
    msg.insert(msg.end(), myClientIdHeader.begin(), myClientIdHeader.end());
    msg.push_back(CLIENT_VERSION);
    append_u16_le(msg, CODE_SEND_MESSAGE_REQ);
    append_u32_le(msg, static_cast<uint32_t>(payload.size()));
    msg.insert(msg.end(), payload.begin(), payload.end());
    return msg;
}

std::vector<uint8_t> Protocol::buildPullWaitingReq(
    const std::array<uint8_t,16>& myClientIdHeader)
{
    std::vector<uint8_t> msg;
    msg.reserve(16 + 1 + 2 + 4);
    msg.insert(msg.end(), myClientIdHeader.begin(), myClientIdHeader.end());
    msg.push_back(CLIENT_VERSION);
    append_u16_le(msg, CODE_PULL_WAITING_REQ);
    append_u32_le(msg, 0);
    return msg;
}

// helpers to read little-endian
static uint32_t rd_u32_le(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

bool Protocol::isOk(const ServerReply& r, uint16_t expectedCode) {
    return r.version == SERVER_VERSION_EXPECTED && r.code == expectedCode;
}

std::vector<ClientEntry> Protocol::parseClientsListPayload(const std::vector<uint8_t>& payload) {
    std::vector<ClientEntry> out;
    if (payload.size() % ENTRY_TOTAL != 0) return out;
    const size_t n = payload.size() / ENTRY_TOTAL;
    out.reserve(n);
    for (size_t i=0;i<n;++i) {
        const uint8_t* base = payload.data() + i*ENTRY_TOTAL;
        ClientEntry e;
        std::copy_n(base, 16, e.id.begin());
        const char* name = reinterpret_cast<const char*>(base + ENTRY_UUID_LEN);
        size_t len = 0; while (len < ENTRY_NAME_LEN && name[len] != '\0') ++len;
        e.name.assign(name, len);
        out.push_back(std::move(e));
    }
    return out;
}

std::vector<WaitingMessage> Protocol::parseWaitingMessagesPayload(const std::vector<uint8_t>& payload) {
    std::vector<WaitingMessage> out;
    size_t pos = 0;
    while (pos + 16 + 4 + 1 + 4 <= payload.size()) {
        WaitingMessage m{};
        std::copy_n(payload.data()+pos, 16, m.fromId.begin()); pos += 16;
        m.msgId = rd_u32_le(payload.data()+pos); pos += 4;
        m.type  = payload[pos++];

        uint32_t mlen = rd_u32_le(payload.data()+pos); pos += 4;
        if (pos + mlen > payload.size()) { out.clear(); return out; }
        m.content.assign(payload.begin()+pos, payload.begin()+pos+mlen);
        pos += mlen;
        out.push_back(std::move(m));
    }
    return out;
}

bool Protocol::isSendAck(const ServerReply& r) {
    // Ack must come from the expected server version, use the SEND_MESSAGE_OK code,
    // and carry the fixed-length payload required by the spec.
    return r.version == SERVER_VERSION_EXPECTED
        && r.code    == CODE_SEND_MESSAGE_OK
        && r.payloadSize == SEND_ACK_LEN;
}


