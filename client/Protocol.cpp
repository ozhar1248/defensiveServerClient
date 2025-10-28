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
