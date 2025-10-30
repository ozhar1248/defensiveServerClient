#include "ServerConnection.h"
#include "FileConfig.h"
#include "Protocol.h"
#include "Encryption.h"
#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <vector>
#include <filesystem>
#include <windows.h>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <iomanip>

// DEBUG
static void dump_hex_prefix(const std::vector<uint8_t> &v, size_t n = 16)
{
    std::ios old(nullptr);
    old.copyfmt(std::cout);
    std::cout << std::hex;
    size_t lim = std::min(n, v.size());
    for (size_t i = 0; i < lim; ++i)
    {
        std::cout << (i ? " " : "") << std::setw(2) << std::setfill('0') << (int)v[i];
    }
    std::cout << std::dec;
    std::cout.copyfmt(old);
}
// static void dump_hex_prefix_bytes(const uint8_t *p, size_t len, size_t n = 16)
// {
//     std::vector<uint8_t> tmp(p, p + std::min(len, n));
//     dump_hex_prefix(tmp, n);
// }
// END DEBUG

// Helpers to locate exe dir and my.info
static std::filesystem::path exeDir()
{
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::filesystem::path(std::string(buf, n)).parent_path();
}
static std::filesystem::path myInfoPath()
{
    return exeDir() / "my.info";
}

static bool readAll(SOCKET s, uint8_t *buf, int total)
{
    int got = 0;
    while (got < total)
    {
        int r = recv(s, reinterpret_cast<char *>(buf + got), total - got, 0);
        if (r <= 0)
            return false;
        got += r;
    }
    return true;
}

static bool myInfoExists()
{
    return std::filesystem::exists(myInfoPath());
}

static std::array<uint8_t, 16> zeroClientId()
{
    std::array<uint8_t, 16> id{};
    id.fill(0);
    return id;
}

static void showMenu()
{
    std::cout << "MessageU client at your service.\n\n"
                 "110) Register\n"
                 "120) Request for clients list\n"
                 "130) Request for public key\n"
                 "140) Request for waiting messages\n"
                 "150) Send a text message\n"
                 "151) Send a request for symmetric key\n"
                 "152) Send your symmetric key\n"
                 "0) Exit client\n";
}

// PeerInfo stores information about each known peer
// Includes UUID, public key (if fetched), symmetric key (if exchanged)
typedef std::array<uint8_t, 16> Uuid;
struct PeerInfo
{
    Uuid id;
    std::string publicKeyBase64;
    std::array<uint8_t, 16> symmetricKey;
    bool hasSymmetricKey = false;
};

// Global mapping of username to their info
static std::unordered_map<std::string, PeerInfo> g_peers;

// Converts a UUID to a 32-character hex string
static std::string toHex32(const std::array<uint8_t, 16> &id)
{
    static const char *H = "0123456789abcdef";
    std::string s;
    s.reserve(32);
    for (auto b : id)
    {
        s.push_back(H[(b >> 4) & 0xF]);
        s.push_back(H[b & 0xF]);
    }
    return s;
}

// Fetches the client list from the server and caches it in g_peers
void fetchClientList(ServerConnection &conn, const Uuid &myId)
{
    auto req = Protocol::buildClientsListReq(myId);
    send(conn.getSocket(), (const char *)req.data(), req.size(), 0);
    uint8_t hdr[7];
    recv(conn.getSocket(), (char *)hdr, 7, 0);
    auto rep = Protocol::parseServerReplyHeader(hdr);
    std::vector<uint8_t> payload(rep.payloadSize);
    recv(conn.getSocket(), (char *)payload.data(), payload.size(), 0);

    g_peers.clear();
    size_t count = payload.size() / ENTRY_TOTAL;
    for (size_t i = 0; i < count; ++i)
    {
        const uint8_t *base = payload.data() + i * ENTRY_TOTAL;
        PeerInfo info;
        std::copy_n(base, 16, info.id.begin());
        const char *nameField = reinterpret_cast<const char *>(base + 16);
        std::string name(nameField, strnlen(nameField, ENTRY_NAME_LEN));
        g_peers[name] = info;
    }

    std::cout << "Registered clients:\n";
    for (const auto &[name, _] : g_peers)
    {
        std::cout << " - " << name << "\n";
    }
}

// Resolves sender name based on UUID (used in message listing)
std::string resolveSenderName(const Uuid &id, ServerConnection &conn, const Uuid &myId)
{
    for (const auto &[name, peer] : g_peers)
    {
        if (peer.id == id)
            return name;
    }
    fetchClientList(conn, myId); // Refresh and try again
    for (const auto &[name, peer] : g_peers)
    {
        if (peer.id == id)
            return name;
    }
    return "<unknown:" + toHex32(id) + ">";
}

int main()
{
    // Read server address (server.info)
    std::string ip;
    unsigned short port;
    try
    {
        auto cfg = FileConfig::readServerInfo();
        ip = cfg.first;
        port = cfg.second;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Config error: " << ex.what() << "\n";
        return 2;
    }

    ServerConnection conn(ip, port);
    if (!conn.connectToServer())
    {
        std::cerr << "Unable to connect to the server at " << ip << ":" << port << "\n";
        return 1;
    }

    std::cout << "Connected to " << ip << ":" << port << "\n";

    while (true)
    {
        showMenu();
        std::cout << "\n> ";
        std::string choice;
        if (!std::getline(std::cin, choice))
            break;

        if (choice == "0")
        {
            std::cout << "Client exiting.\n";
            break;
        }
        else if (choice == "110")
        {
            // Registration
            if (myInfoExists())
            {
                std::cerr << "Registration error: 'my.info' already exists (client already registered).\n";
                continue;
            }

            std::string username;
            std::cout << "Enter username (ASCII, <=255): ";
            if (!std::getline(std::cin, username))
                continue;
            if (username.empty())
            {
                std::cerr << "Username cannot be empty.\n";
                continue;
            }

            auto cid = zeroClientId();
            Encryption::RsaKeyPair kp;
            try
            {
                kp = Encryption::GenerateRsaKeypair1024();
            }
            catch (const std::exception &ex)
            {
                std::cerr << "Key generation failed: " << ex.what() << "\n";
                continue;
            }

            auto req = Protocol::buildRegistration(cid, username, kp.publicKeyBase64);

            // send request bytes
            int sent = 0;
            while (sent < (int)req.size())
            {
                int s = send(conn.getSocket(), reinterpret_cast<const char *>(req.data() + sent),
                             (int)req.size() - sent, 0);
                if (s <= 0)
                {
                    std::cerr << "send() failed: " << WSAGetLastError() << "\n";
                    break;
                }
                sent += s;
            }
            if (sent != (int)req.size())
                continue;

            // read server reply header (7 bytes)
            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto reply = Protocol::parseServerReplyHeader(hdr);
            // debug
            std::cout << "[DBG] reg reply code=" << reply.code
                      << " payloadSize=" << reply.payloadSize << "\n";
            // end debug

            // read payload
            std::vector<uint8_t> payload(reply.payloadSize);
            if (reply.payloadSize > 0)
            {
                if (!readAll(conn.getSocket(), payload.data(), (int)payload.size()))
                {
                    std::cerr << "Payload read failed\n";
                    continue;
                }
            }
            if (reply.code == CODE_REGISTRATION_OK && payload.size() == 16)
            {
                std::array<uint8_t, 16> uid{};
                std::copy_n(payload.data(), 16, uid.data());

                try
                {
                    FileConfig::writeMyInfo(username, uid, kp.privateKeyBase64);
                    std::cout << "Registration successful. my.info created.\n";
                }
                catch (const std::exception &ex)
                {
                    std::cerr << "Registration succeeded but saving key failed: " << ex.what() << "\n";
                }
            }
            else
            {
                std::cerr << "Server responded with error or unexpected payload.\n";
            }
        }
        else if (choice == "120")
        {
            // Must be registered (my.info present)
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (const std::exception &)
            {
                std::cerr << "Registration error: 'my.info' not found. Please register first.\n";
                continue;
            }
            // Build and send request
            auto req = Protocol::buildClientsListReq(myId);
            int sent = 0;
            while (sent < (int)req.size())
            {
                int s = send(conn.getSocket(), reinterpret_cast<const char *>(req.data() + sent),
                             (int)req.size() - sent, 0);
                if (s <= 0)
                {
                    std::cerr << "send() failed: " << WSAGetLastError() << "\n";
                    break;
                }
                sent += s;
            }
            if (sent != (int)req.size())
                continue;
            // Read server reply header
            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto reply = Protocol::parseServerReplyHeader(hdr);

            // Read payload
            std::vector<uint8_t> payload(reply.payloadSize);
            if (reply.payloadSize > 0)
            {
                if (!readAll(conn.getSocket(), payload.data(), (int)payload.size()))
                {
                    std::cerr << "server responded with an error\n";
                    continue;
                }
            }

            if (reply.version != SERVER_VERSION_EXPECTED || reply.code == CODE_ERROR)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            if (reply.code != CODE_CLIENTS_LIST_OK)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            // Parse list: payload is N entries of (16 uuid + 255 name[NUL-padded])
            if (payload.size() % ENTRY_TOTAL != 0)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            size_t count = payload.size() / ENTRY_TOTAL;
            if (count == 0)
            {
                std::cout << "No other clients registered.\n";
                continue;
            }

            std::cout << "Registered clients:\n";
            g_peers.clear(); // Clear old list before re-caching
            for (size_t i = 0; i < count; ++i)
            {
                const uint8_t *base = payload.data() + i * ENTRY_TOTAL;
                std::array<uint8_t, 16> id{};
                std::copy_n(base, 16, id.data());
                const char *nameField = reinterpret_cast<const char *>(base + ENTRY_UUID_LEN);
                size_t len = 0;
                while (len < ENTRY_NAME_LEN && nameField[len] != '\0')
                    ++len;
                std::string username(nameField, len);
                PeerInfo info;
                info.id = id;
                g_peers[username] = info;
                std::cout << " - " << username << "\n";
            }
        }
        else if (choice == "130")
        {
            // Must be registered
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Registration error: 'my.info' not found. Please register first.\n";
                continue;
            }

            std::string targetUsername;
            std::cout << "Enter destination username: ";
            if (!std::getline(std::cin, targetUsername))
                continue;

            auto it = g_peers.find(targetUsername);
            if (it == g_peers.end())
            {
                std::cerr << "Error: Username not found in cached client list. Run 120 first.\n";
                continue;
            }
            std::array<uint8_t, 16> targetId = it->second.id;
            auto req = Protocol::buildPublicKeyReq(myId, targetId);

            int sent = 0;
            while (sent < (int)req.size())
            {
                int s = send(conn.getSocket(), reinterpret_cast<const char *>(req.data() + sent),
                             (int)req.size() - sent, 0);
                if (s <= 0)
                {
                    std::cerr << "send() failed: " << WSAGetLastError() << "\n";
                    break;
                }
                sent += s;
            }
            if (sent != (int)req.size())
                continue;

            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            auto reply = Protocol::parseServerReplyHeader(hdr);
            std::vector<uint8_t> payload(reply.payloadSize);
            if (reply.payloadSize > 0 &&
                !readAll(conn.getSocket(), payload.data(), (int)payload.size()))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            // debug
            std::cout << "[DBG] pubkey reply code=" << reply.code
                      << " payloadSize=" << reply.payloadSize << "\n";
            // end debug
            if (reply.version != SERVER_VERSION_EXPECTED || reply.code != CODE_PUBLIC_KEY_OK || payload.size() != (16 + RESP_PUBKEY_LEN))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            const char *keyField = reinterpret_cast<const char *>(payload.data() + 16);
            size_t keyLen = RESP_PUBKEY_LEN;
            for (size_t i = 0; i < RESP_PUBKEY_LEN; ++i)
            {
                if (keyField[i] == '\0')
                {
                    keyLen = i;
                    break;
                }
            }
            std::string pubKey(keyField, keyLen);
            // Validate that pubKey contains only valid base64 characters
            if (pubKey.empty() || pubKey.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n") != std::string::npos)
            {
                std::cerr << "Invalid Base64 format for public key. Aborting.\n";
                continue;
            }

            g_peers[targetUsername].publicKeyBase64 = pubKey;
            // DEBUG
            std::cout << "[DBG] pubkey len (base64): " << pubKey.size() << "\n";
            if (!pubKey.empty())
            {
                std::cout << "[DBG] pubkey prefix: " << pubKey.substr(0, 32) << "...\n";
            }
            // end debug
            std::cout << "Public key for " << targetUsername << " successfully cached.\n";
        }

        else if (choice == "150")
        {
            // requires registration
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Registration error: 'my.info' not found. Please register first.\n";
                continue;
            }

            std::string toName;
            std::cout << "Enter destination username: ";
            if (!std::getline(std::cin, toName))
                continue;

            auto it = g_peers.find(toName);
            if (it == g_peers.end())
            {
                std::cerr << "User not found. Please run option 120 to refresh list.\n";
                continue;
            }
            std::array<uint8_t, 16> toId = it->second.id;

            std::string text;
            std::cout << "Enter message text: ";
            if (!std::getline(std::cin, text))
                continue;

            if (it == g_peers.end() || !it->second.hasSymmetricKey)
            {
                std::cerr << "can't encrypt: no symmetric key. Use 151/152 first.\n";
                continue;
            }
            std::vector<uint8_t> plain(text.begin(), text.end());
            auto cipher = Encryption::AesCbcEncryptZeroIV(it->second.symmetricKey, plain);

            auto req = Protocol::buildSendMessageReq(myId, toId, /*type*/ 3, cipher);
            int sent = 0;
            while (sent < (int)req.size())
            {
                int s = send(conn.getSocket(), (const char *)req.data() + sent, (int)req.size() - sent, 0);
                if (s <= 0)
                {
                    std::cerr << "send() failed: " << WSAGetLastError() << "\n";
                    break;
                }
                sent += s;
            }
            if (sent != (int)req.size())
                continue;

            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto rep = Protocol::parseServerReplyHeader(hdr);
            std::vector<uint8_t> payload(rep.payloadSize);
            if (rep.payloadSize && !readAll(conn.getSocket(), payload.data(), (int)payload.size()))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            if (rep.version != SERVER_VERSION_EXPECTED || rep.code != CODE_SEND_MESSAGE_OK || payload.size() != 20)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            std::cout << "Message sent to " << toName << ".\n";
        }
        else if (choice == "151")
        {
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Registration error: 'my.info' not found. Please register first.\n";
                continue;
            }

            std::string toName;
            std::cout << "Enter destination username: ";
            if (!std::getline(std::cin, toName))
                continue;

            auto it = g_peers.find(toName);
            if (it == g_peers.end())
            {
                std::cerr << "User not found. Please run option 120 to refresh list.\n";
                continue;
            }
            std::array<uint8_t, 16> toId = it->second.id;

            std::vector<uint8_t> empty;
            auto req = Protocol::buildSendMessageReq(myId, toId, /*type*/ 1, empty);
            int sent = 0;
            while (sent < (int)req.size())
            {
                int s = send(conn.getSocket(), (const char *)req.data() + sent, (int)req.size() - sent, 0);
                if (s <= 0)
                {
                    std::cerr << "send() failed: " << WSAGetLastError() << "\n";
                    break;
                }
                sent += s;
            }
            if (sent != (int)req.size())
                continue;

            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto rep = Protocol::parseServerReplyHeader(hdr);
            std::vector<uint8_t> payload(rep.payloadSize);
            if (rep.payloadSize && !readAll(conn.getSocket(), payload.data(), (int)payload.size()))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            if (rep.version != SERVER_VERSION_EXPECTED || rep.code != CODE_SEND_MESSAGE_OK)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            std::cout << "Symmetric key request sent to " << toName << ".\n";
        }
        else if (choice == "152")
        {
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Registration error: 'my.info' not found. Please register first.\n";
                continue;
            }

            std::string toName;
            std::cout << "Enter destination username: ";
            if (!std::getline(std::cin, toName))
                continue;

            auto it = g_peers.find(toName);
            if (it == g_peers.end())
            {
                std::cerr << "User not found. Please run option 120 to refresh list.\n";
                continue;
            }
            std::array<uint8_t, 16> toId = it->second.id;

            // fetch public key of destination (602)
            if (g_peers[toName].publicKeyBase64.empty())
            {
                std::cerr << "Missing public key. Use option 130 first.\n";
                continue;
            }

            // symmetric key (generate or reuse)
            auto &peer = g_peers[toName];
            if (!peer.hasSymmetricKey)
            {
                peer.symmetricKey = Encryption::GenerateAesKey();
                peer.hasSymmetricKey = true;
            }
            std::vector<uint8_t> keyRaw(peer.symmetricKey.begin(), peer.symmetricKey.end());

            std::vector<uint8_t> keyEnc;
            try
            {
                // peer public key is already cached in g_peers[toName].publicKeyBase64
                keyEnc = Encryption::RsaEncryptOaepWithBase64Pub(
                    g_peers[toName].publicKeyBase64,
                    keyRaw // this is the std::vector<uint8_t> you created from the 16-byte AES key
                );
                // DEBUG
                std::cout << "[DBG] RSA ciphertext size: " << keyEnc.size() << " (expect 128 for RSA-1024)\n";
                std::cout << "[DBG] RSA ciphertext prefix: ";
                dump_hex_prefix(keyEnc);
                std::cout << "\n";
                // END debug
            }
            catch (const std::exception &ex)
            {
                std::cerr << "Encryption error: " << ex.what() << "\n";
                continue;
            }

            auto req = Protocol::buildSendMessageReq(myId, toId, /*type*/ 2, keyEnc);
            int sent = 0;
            while (sent < (int)req.size())
            {
                int s = send(conn.getSocket(), (const char *)req.data() + sent, (int)req.size() - sent, 0);
                if (s <= 0)
                {
                    std::cerr << "send() failed: " << WSAGetLastError() << "\n";
                    break;
                }
                sent += s;
            }
            if (sent != (int)req.size())
                continue;

            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto rep = Protocol::parseServerReplyHeader(hdr);
            std::vector<uint8_t> payload(rep.payloadSize);
            if (rep.payloadSize && !readAll(conn.getSocket(), payload.data(), (int)payload.size()))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            if (rep.version != SERVER_VERSION_EXPECTED || rep.code != CODE_SEND_MESSAGE_OK)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            std::cout << "Symmetric key sent to " << toName << ".\n";
        }
        else if (choice == "140")
        {
            std::array<uint8_t, 16> myId{};
            std::string myName;
            try
            {
                auto me = FileConfig::readFullMyInfo();
                myName = std::get<0>(me);
                myId = std::get<1>(me);
            }
            catch (...)
            {
                std::cerr << "Registration error: 'my.info' not found. Please register first.\n";
                continue;
            }

            auto req = Protocol::buildPullWaitingReq(myId);
            int sent = 0;
            while (sent < (int)req.size())
            {
                int s = send(conn.getSocket(), (const char *)req.data() + sent, (int)req.size() - sent, 0);
                if (s <= 0)
                {
                    std::cerr << "send() failed: " << WSAGetLastError() << "\n";
                    break;
                }
                sent += s;
            }
            if (sent != (int)req.size())
                continue;

            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto rep = Protocol::parseServerReplyHeader(hdr);
            std::vector<uint8_t> payload(rep.payloadSize);
            if (rep.payloadSize && !readAll(conn.getSocket(), payload.data(), (int)payload.size()))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            if (rep.version != SERVER_VERSION_EXPECTED || rep.code == CODE_ERROR)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            if (rep.code != CODE_PULL_WAITING_OK)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            // Parse stream of: fromId(16) + msgId(4) + type(1) + size(4) + content
            size_t pos = 0;
            while (pos + 16 + 4 + 1 + 4 <= payload.size())
            {
                std::array<uint8_t, 16> fromId{};
                std::copy_n(payload.data() + pos, 16, fromId.data());
                pos += 16;
                pos += 4;
                uint8_t mtype = payload[pos];
                pos += 1;
                uint32_t mlen = payload[pos] | (payload[pos + 1] << 8) | (payload[pos + 2] << 16) | (payload[pos + 3] << 24);
                pos += 4;
                if (pos + mlen > payload.size())
                {
                    std::cerr << "server responded with an error\n";
                    break;
                }
                std::vector<uint8_t> mcontent(payload.begin() + pos, payload.begin() + pos + mlen);
                pos += mlen;

                // DEBUG: message header
                std::cout << "[DBG] msg type=" << (int)mtype
                          << " len=" << mlen << " from=" << toHex32(fromId) << "\n";
                std::cout << "[DBG] content prefix (hex): ";
                dump_hex_prefix(mcontent);
                std::cout << "\n";
                // END DEBUG
                //  resolve name (try cache, else show hex)
                std::string fromName = resolveSenderName(fromId, conn, myId);

                std::cout << "From: " << fromName << "\nContent:\n";
                if (mtype == 1)
                {
                    std::cout << "Request for symmetric key\n";
                }
                else if (mtype == 2)
                {
                    std::cout << "symmetric key received\n";
                    try
                    {
                        // Load my private key (Base64 DER) from my.info
                        auto [myName2, myId2, myBase64] = FileConfig::readFullMyInfo();
                        //DEBUG
                         std::cout << "[DBG] SYM-KEY message len: " << mcontent.size()
                                  << " (expect 128 for RSA-1024)\n";
                        if (mcontent.size() != 128)
                        {
                            std::cerr << "[DBG] WARNING: ciphertext size unexpected; likely not raw RSA block.\n";
                        }
                        //END DEBUG
                        bool ok = false;
                        
                        //  Decrypt the received symmetric key (RSA-OAEP)
                        auto recovered = Encryption::RsaDecryptOaepWithBase64Priv(myBase64, mcontent, ok);

                        // debug
                       

                        // after decryption call:
                        std::cout << "[DBG] RSA decrypt ok=" << (ok ? "true" : "false")
                                  << " recovered len=" << recovered.size() << "\n";
                        if (ok && recovered.size() >= 16)
                        {
                            std::cout << "[DBG] recovered key prefix: ";
                            dump_hex_prefix(recovered);
                            std::cout << "\n";
                        }
                        // END DEBUG

                        if (!ok || recovered.size() < 16)
                        {
                            std::cerr << "Failed to decrypt symmetric key (invalid data).\n";
                            continue;
                        }

                        std::array<uint8_t, 16> key{};
                        std::copy_n(recovered.begin(), 16, key.begin());
                        g_peers[fromName].symmetricKey = key;
                        g_peers[fromName].hasSymmetricKey = true;

                        std::cout << "Symmetric key stored for " << fromName << ".\n";
                    }
                    catch (const std::exception &ex)
                    {
                        std::cerr << "Failed to decrypt symmetric key: " << ex.what() << "\n";
                    }
                }
                else if (mtype == 3)
                {
                    auto it = g_peers.find(fromName);
                    if (it == g_peers.end() || !it->second.hasSymmetricKey)
                    {
                        std::cout << "can't decrypt message\n";
                    }
                    else
                    {
                        bool ok = false;
                        auto plain = Encryption::AesCbcDecryptZeroIV(it->second.symmetricKey, mcontent, ok);

                        if (!ok)
                            std::cout << "can't decrypt message\n";
                        else
                            std::cout << std::string(plain.begin(), plain.end()) << "\n";
                    }
                }
                else
                {
                    std::cout << "(unknown type)\n";
                }
                std::cout << "------<EOM>-------\n\n";
            }
        }
        else
        {
            std::cout << "Unknown option.\n";
        }
    }

    return 0;
}
