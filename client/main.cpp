#include "ServerConnection.h"
#include "FileConfig.h"
#include "Protocol.h"
#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <vector>
#include <filesystem>
#include <windows.h>
#include <algorithm>

// Helpers to locate exe dir and me.info
static std::filesystem::path exeDir() {
    char buf[MAX_PATH]; DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return std::filesystem::path(std::string(buf, n)).parent_path();
}
static std::filesystem::path meInfoPath() {
    return exeDir() / "me.info";
}

static bool readAll(SOCKET s, uint8_t* buf, int total) {
    int got = 0;
    while (got < total) {
        int r = recv(s, reinterpret_cast<char*>(buf + got), total - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

static bool meInfoExists() {
    return std::filesystem::exists(meInfoPath());
}
static void saveMeInfo(const std::string& name, const std::array<uint8_t,16>& id) {
    std::ofstream out(meInfoPath(), std::ios::binary | std::ios::trunc);
    out << name << "\n";
    // store UUID as 16 raw bytes on line 2 in hex
    static const char* hex = "0123456789abcdef";
    for (auto b : id) { out << hex[(b>>4)&0xF] << hex[b&0xF]; }
    out << "\n";
}

static std::array<uint8_t,16> zeroClientId() {
    std::array<uint8_t,16> id{}; id.fill(0); return id;
}

static void showMenu() {
    std::cout <<
"MessageU client at your service.\n\n"
"110) Register\n"
"120) Request for clients list\n"
"130) Request for public key\n"
"140) Request for waiting messages\n"
"150) Send a text message\n"
"151) Send a request for symmetric key\n"
"152) Send your symmetric key\n"
"0) Exit client\n";
}

int main() {
    // Read server address (server.info)
    std::string ip; unsigned short port;
    try {
        auto cfg = FileConfig::readServerInfo();
        ip = cfg.first; port = cfg.second;
    } catch (const std::exception& ex) {
        std::cerr << "Config error: " << ex.what() << "\n";
        return 2;
    }

    ServerConnection conn(ip, port);
    if (!conn.connectToServer()) {
        std::cerr << "Unable to connect to the server at " << ip << ":" << port << "\n";
        return 1;
    }

    std::cout << "Connected to " << ip << ":" << port << "\n";

    while (true) {
        showMenu();
        std::cout << "\n> ";
        std::string choice;
        if (!std::getline(std::cin, choice)) break;

        if (choice == "0") {
            std::cout << "Client exiting.\n";
            break;
        } else if (choice == "110") {
            // Registration
            if (meInfoExists()) {
                std::cerr << "Registration error: 'me.info' already exists (client already registered).\n";
                continue;
            }

            std::string username;
            std::cout << "Enter username (ASCII, <=255): ";
            if (!std::getline(std::cin, username)) continue;

            std::string publicKey;
            std::cout << "Enter public key (ASCII, <=150): ";
            if (!std::getline(std::cin, publicKey)) continue;

            auto cid = zeroClientId();
            auto req = Protocol::buildRegistration(cid, username, publicKey);
            // send request bytes
            int sent = 0;
            while (sent < (int)req.size()) {
                int s = send(conn.getSocket(), reinterpret_cast<const char*>(req.data()+sent),
                             (int)req.size()-sent, 0);
                if (s <= 0) { std::cerr << "send() failed: " << WSAGetLastError() << "\n"; break; }
                sent += s;
            }
            if (sent != (int)req.size()) continue;

            // read server reply header (7 bytes)
            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7)) {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto reply = Protocol::parseServerReplyHeader(hdr);

            // read payload
            std::vector<uint8_t> payload;
            payload.resize(reply.payloadSize);
            if (reply.payloadSize > 0) {
                if (!readAll(conn.getSocket(), payload.data(), (int)payload.size())) {
                    std::cerr << "server responded with an error\n";
                    continue;
                }
            }
            reply.payload = std::move(payload);

            if (reply.code == CODE_ERROR || reply.version != SERVER_VERSION_EXPECTED) {
                std::cerr << "server responded with an error\n";
                continue;
            }
            if (reply.code == CODE_REGISTRATION_OK && reply.payload.size() == 16) {
                std::array<uint8_t,16> uid{};
                std::copy_n(reply.payload.data(), 16, uid.data());
                saveMeInfo(username, uid);
                std::cout << "Registration successful.\n";
            } else {
                std::cerr << "server responded with an error\n";
            }
        } else if (choice == "120") {
            // Must be registered (me.info present)
            std::array<uint8_t,16> myId{};
            std::string myName;
            try {
                auto me = FileConfig::readMeInfo();
                myName = me.first;
                myId = me.second;
            } catch (const std::exception&) {
                std::cerr << "Registration error: 'me.info' not found. Please register first.\n";
                continue;
            }
            // Build and send request
            auto req = Protocol::buildClientsListReq(myId);
            int sent = 0;
            while (sent < (int)req.size()) {
                int s = send(conn.getSocket(), reinterpret_cast<const char*>(req.data()+sent),
                            (int)req.size()-sent, 0);
                if (s <= 0) { std::cerr << "send() failed: " << WSAGetLastError() << "\n"; break; }
                sent += s;
            }
            if (sent != (int)req.size()) continue;
            // Read server reply header
            uint8_t hdr[7];
            if (!readAll(conn.getSocket(), hdr, 7)) {
                std::cerr << "server responded with an error\n";
                continue;
            }
            auto reply = Protocol::parseServerReplyHeader(hdr);

            // Read payload
            std::vector<uint8_t> payload(reply.payloadSize);
            if (reply.payloadSize > 0) {
                if (!readAll(conn.getSocket(), payload.data(), (int)payload.size())) {
                    std::cerr << "server responded with an error\n";
                    continue;
                }
            }

            if (reply.version != SERVER_VERSION_EXPECTED || reply.code == CODE_ERROR) {
                std::cerr << "server responded with an error\n";
                continue;
            }

            if (reply.code != CODE_CLIENTS_LIST_OK) {
                std::cerr << "server responded with an error\n";
                continue;
            }

            // Parse list: payload is N entries of (16 uuid + 255 name[NUL-padded])
            if (payload.size() % ENTRY_TOTAL != 0) {
                std::cerr << "server responded with an error\n";
                continue;
            }
            size_t count = payload.size() / ENTRY_TOTAL;
            if (count == 0) {
                std::cout << "No other clients registered.\n";
                continue;
            }

            std::cout << "Registered clients:\n";
            for (size_t i = 0; i < count; ++i) {
                const uint8_t* base = payload.data() + i * ENTRY_TOTAL;
                // skip 16-byte UUID: base[0..15]
                const char* nameField = reinterpret_cast<const char*>(base + ENTRY_UUID_LEN);
                // find NUL terminator within 255 bytes
                size_t len = 0;
                while (len < ENTRY_NAME_LEN && nameField[len] != '\0') ++len;
                std::string username(nameField, len);
                std::cout << " - " << username << "\n";
            }
        } else if (choice == "130" || choice == "140"
                || choice == "150" || choice == "151" || choice == "152") {
            std::cout << "(Not implemented yet)\n";
        } else {
            std::cout << "Unknown option.\n";
        }
    }

    return 0;
}
