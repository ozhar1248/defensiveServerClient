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

#include <osrng.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/pssr.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>

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
static void saveMyInfo(const std::string &name, const std::array<uint8_t, 16> &id)
{
    std::ofstream out(myInfoPath(), std::ios::binary | std::ios::trunc);
    out << name << "\n";
    // store UUID as 16 raw bytes on line 2 in hex
    static const char *hex = "0123456789abcdef";
    for (auto b : id)
    {
        out << hex[(b >> 4) & 0xF] << hex[b & 0xF];
    }
    out << "\n";
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

static uint8_t hexNibbleLocal(char c)
{
    if (c >= '0' && c <= '9')
        return uint8_t(c - '0');
    if (c >= 'a' && c <= 'f')
        return uint8_t(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return uint8_t(c - 'A' + 10);
    return 255;
}
static bool parseHex32ToBytes16(const std::string &hex, std::array<uint8_t, 16> &out)
{
    if (hex.size() != 32)
        return false;
    for (size_t i = 0; i < 16; ++i)
    {
        uint8_t hi = hexNibbleLocal(hex[2 * i]);
        uint8_t lo = hexNibbleLocal(hex[2 * i + 1]);
        if (hi == 255 || lo == 255)
            return false;
        out[i] = uint8_t((hi << 4) | lo);
    }
    return true;
}

static std::unordered_map<std::string, std::array<uint8_t, 16>> g_nameToId;
static std::unordered_map<std::string, std::array<uint8_t, 16>> g_symKeys; // 16-byte AES keys

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

static bool resolveUserIdByName(ServerConnection &conn, const std::array<uint8_t, 16> &myId,
                                const std::string &name, std::array<uint8_t, 16> &outId,
                                std::function<bool(const uint8_t *, int)> readAllFn)
{
    auto it = g_nameToId.find(name);
    if (it != g_nameToId.end())
    {
        outId = it->second;
        return true;
    }

    // fetch fresh list (reuse code path 120 silently)
    auto req = Protocol::buildClientsListReq(myId);
    int sent = 0;
    while (sent < (int)req.size())
    {
        int s = send(conn.getSocket(), (const char *)req.data() + sent, (int)req.size() - sent, 0);
        if (s <= 0)
            return false;
        sent += s;
    }
    uint8_t hdr[7];
    if (!readAllFn(hdr, 7))
        return false;
    auto rep = Protocol::parseServerReplyHeader(hdr);
    if (rep.code != CODE_CLIENTS_LIST_OK)
        return false;
    std::vector<uint8_t> payload(rep.payloadSize);
    if (rep.payloadSize && !readAllFn(payload.data(), (int)payload.size()))
        return false;
    if (payload.size() % ENTRY_TOTAL)
        return false;

    size_t n = payload.size() / ENTRY_TOTAL;
    for (size_t i = 0; i < n; ++i)
    {
        const uint8_t *base = payload.data() + i * ENTRY_TOTAL;
        std::array<uint8_t, 16> id{};
        std::copy_n(base, 16, id.data());
        const char *nm = (const char *)(base + 16);
        size_t len = 0;
        while (len < ENTRY_NAME_LEN && nm[len] != '\0')
            ++len;
        std::string uname(nm, len);
        g_nameToId[uname] = id;
    }
    auto it2 = g_nameToId.find(name);
    if (it2 == g_nameToId.end())
        return false;
    outId = it2->second;
    return true;
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
            auto cid = zeroClientId();
            CryptoPP::RSA::PrivateKey privateKey;
            std::string publicKeyBase64;

            try
            {

                CryptoPP::AutoSeededRandomPool rng;
                privateKey.GenerateRandomWithKeySize(rng, 1024);
                CryptoPP::RSA::PublicKey publicKey(privateKey);

                // Export public key in X.509 Base64 format
                CryptoPP::ByteQueue pubQueue;
                publicKey.DEREncode(pubQueue);
                CryptoPP::Base64Encoder pubEncoder(new CryptoPP::StringSink(publicKeyBase64), false);
                pubQueue.CopyTo(pubEncoder);
                pubEncoder.MessageEnd();
            }
            catch (const std::exception &ex)
            {
                std::cerr << "Key generation failed: " << ex.what() << "\n";
                continue;
            }

            auto req = Protocol::buildRegistration(cid, username, publicKeyBase64);
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
                    // Convert the private key to Base64 DER format
                    std::string privateKeyBase64;
                    CryptoPP::ByteQueue privQueue;
                    privateKey.DEREncode(privQueue);
                    CryptoPP::Base64Encoder privEncoder(new CryptoPP::StringSink(privateKeyBase64), false);
                    privQueue.CopyTo(privEncoder);
                    privEncoder.MessageEnd();

                    // Write to my.info
                    FileConfig::writeMyInfo(username, uid, privateKeyBase64);
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
            for (size_t i = 0; i < count; ++i)
            {
                const uint8_t *base = payload.data() + i * ENTRY_TOTAL;
                // skip 16-byte UUID: base[0..15]
                const char *nameField = reinterpret_cast<const char *>(base + ENTRY_UUID_LEN);
                // find NUL terminator within 255 bytes
                size_t len = 0;
                while (len < ENTRY_NAME_LEN && nameField[len] != '\0')
                    ++len;
                std::string username(nameField, len);
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

            std::string targetHex;
            std::cout << "Enter target client's 16-byte ID in hex (32 hex chars, no dashes): ";
            if (!std::getline(std::cin, targetHex))
                continue;

            std::array<uint8_t, 16> targetId{};
            if (!parseHex32ToBytes16(targetHex, targetId))
            {
                std::cerr << "Invalid hex format.\n";
                continue;
            }

            auto req = Protocol::buildPublicKeyReq(myId, targetId);

            // send request
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

            // read reply header
            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto reply = Protocol::parseServerReplyHeader(hdr);

            // read payload
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
            if (reply.code != CODE_PUBLIC_KEY_OK || reply.payload.size() != (16 + RESP_PUBKEY_LEN))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            // parse response: first 16 bytes = client id, next 160 = ASCII public key (NUL-padded)
            const uint8_t *base = payload.data();
            // const uint8_t* idBytes = base;  // (we already know target; you could check equality)
            const char *keyField = reinterpret_cast<const char *>(base + 16);

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
            std::cout << "Public key: " << pubKey << "\n";
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

            std::array<uint8_t, 16> toId{};
            if (!resolveUserIdByName(conn, myId, toName, toId,
                                     [&](const uint8_t *buf, int n)
                                     { return readAll(conn.getSocket(), (uint8_t *)buf, n); }))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            std::string text;
            std::cout << "Enter message text: ";
            if (!std::getline(std::cin, text))
                continue;

            // must have symmetric key for this peer
            auto kit = g_symKeys.find(toName);
            if (kit == g_symKeys.end())
            {
                std::cerr << "can't decrypt/encrypt: no symmetric key. Use 151/152 first.\n";
                continue;
            }
            std::vector<uint8_t> plain(text.begin(), text.end());
            auto cipher = Encryption::AesCbcEncryptZeroIV(kit->second, plain);

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

            std::array<uint8_t, 16> toId{};
            if (!resolveUserIdByName(conn, myId, toName, toId,
                                     [&](const uint8_t *buf, int n)
                                     { return readAll(conn.getSocket(), (uint8_t *)buf, n); }))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

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

            std::array<uint8_t, 16> toId{};
            if (!resolveUserIdByName(conn, myId, toName, toId,
                                     [&](const uint8_t *buf, int n)
                                     { return readAll(conn.getSocket(), (uint8_t *)buf, n); }))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }

            // fetch public key of destination (602)
            auto preq = Protocol::buildPublicKeyReq(myId, toId);
            int psent = 0;
            while (psent < (int)preq.size())
            {
                int s = send(conn.getSocket(), (const char *)preq.data() + psent, (int)preq.size() - psent, 0);
                if (s <= 0)
                {
                    std::cerr << "send() failed: " << WSAGetLastError() << "\n";
                    break;
                }
                psent += s;
            }
            if (psent != (int)preq.size())
                continue;
            uint8_t phdr[7];
            if (!readAll(conn.getSocket(), phdr, 7))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto prep = Protocol::parseServerReplyHeader(phdr);
            std::vector<uint8_t> ppayload(prep.payloadSize);
            if (prep.payloadSize && !readAll(conn.getSocket(), ppayload.data(), (int)ppayload.size()))
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            if (prep.version != SERVER_VERSION_EXPECTED || prep.code != CODE_PUBLIC_KEY_OK || ppayload.size() < 16)
            {
                std::cerr << "server responded with an error\n";
                continue;
            }
            // parse pubkey (next 160 bytes, NUL-padded)
            const char *kf = (const char *)(ppayload.data() + 16);
            size_t klen = std::min<size_t>(RESP_PUBKEY_LEN, prep.payloadSize - 16);
            size_t term = klen;
            for (size_t i = 0; i < klen; ++i)
            {
                if (kf[i] == '\0')
                {
                    term = i;
                    break;
                }
            }
            std::string peerPub(kf, term);

            // symmetric key (generate or reuse)
            auto it = g_symKeys.find(toName);
            if (it == g_symKeys.end())
            {
                g_symKeys[toName] = Encryption::GenerateAesKey();
                it = g_symKeys.find(toName);
            }
            std::vector<uint8_t> keyRaw(it->second.begin(), it->second.end());
            auto keyEnc = Encryption::RsaEncryptOaepWithBase64X509Pub(peerPub, keyRaw);

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

                // resolve name (try cache, else show hex)
                std::string fromName = "<unknown>";
                for (const auto &kv : g_nameToId)
                    if (kv.second == fromId)
                    {
                        fromName = kv.first;
                        break;
                    }
                if (fromName == "<unknown>")
                    fromName = toHex32(fromId);

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
                        // 1. Load my private key from my.info
                        auto [myName, myId, myBase64] = FileConfig::readFullMyInfo();

                        // 2. Decode Base64 -> DER -> ByteQueue
                        CryptoPP::ByteQueue q;
                        CryptoPP::StringSource ss(myBase64, true, new CryptoPP::Base64Decoder);
                        ss.TransferTo(q);
                        q.MessageEnd();

                        // 3. Load RSA private key from queue
                        CryptoPP::RSA::PrivateKey priv;
                        priv.BERDecodePrivateKey(q, false, q.MaxRetrievable());

                        // 4. Decrypt the message content (ciphertext) with OAEP-SHA
                        CryptoPP::AutoSeededRandomPool rng;
                        CryptoPP::RSAES_OAEP_SHA_Decryptor dec(priv);
                        std::string recovered;
                        CryptoPP::StringSource ss2(
                            mcontent.data(), mcontent.size(), true,
                            new CryptoPP::PK_DecryptorFilter(rng, dec, new CryptoPP::StringSink(recovered)));

                        // 5. recovered now holds the 16-byte symmetric AES key
                        if (recovered.size() != 16)
                            std::cerr << "Warning: unexpected symmetric key size (" << recovered.size() << ")\n";

                        std::array<uint8_t, 16> key{};
                        std::copy_n(recovered.begin(), std::min<size_t>(16, recovered.size()), key.begin());
                        g_symKeys[fromName] = key;
                        std::cout << "Symmetric key stored for " << fromName << ".\n";
                    }
                    catch (const std::exception &ex)
                    {
                        std::cerr << "Failed to decrypt symmetric key: " << ex.what() << "\n";
                    }
                }
                else if (mtype == 3)
                {
                    auto kit = g_symKeys.find(fromName);
                    if (kit == g_symKeys.end())
                    {
                        std::cout << "can't decrypt message\n";
                    }
                    else
                    {
                        bool ok = false;
                        auto plain = Encryption::AesCbcDecryptZeroIV(kit->second, mcontent, ok);
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
