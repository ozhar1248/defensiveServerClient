#include "FileConfig.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <stdexcept>

using namespace std;

static filesystem::path exeDirFC() {
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return filesystem::path(string(buf, n)).parent_path();
}

pair<string, unsigned short> FileConfig::readServerInfo() {
    auto path = exeDirFC() / "server.info";
    if (!filesystem::exists(path)) {
        throw runtime_error("server.info not found at: " + path.string());
    }
    ifstream in(path);
    string line; getline(in, line); // IP:PORT
    size_t pos = line.find(':');
    string ip = line.substr(0, pos);
    unsigned short port = static_cast<unsigned short>(stoi(line.substr(pos + 1)));
    return { ip, port };
}

// --- NEW ---
static uint8_t hexNibble(char c) {
    if (c >= '0' && c <= '9') return uint8_t(c - '0');
    if (c >= 'a' && c <= 'f') return uint8_t(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return uint8_t(c - 'A' + 10);
    throw runtime_error("invalid hex");
}
static array<uint8_t,16> hexToBytes16(const string& hex) {
    if (hex.size() < 32) throw runtime_error("UUID hex too short");
    array<uint8_t,16> out{};
    for (size_t i = 0; i < 16; ++i) {
        uint8_t hi = hexNibble(hex[2*i]);
        uint8_t lo = hexNibble(hex[2*i + 1]);
        out[i] = uint8_t((hi << 4) | lo);
    }
    return out;
}

pair<string, array<uint8_t,16>> FileConfig::readMeInfo() {
    auto path = exeDirFC() / "me.info";
    if (!filesystem::exists(path)) {
        throw runtime_error("me.info not found at: " + path.string());
    }
    ifstream in(path, ios::binary);
    string name;
    string hexline;
    getline(in, name);
    getline(in, hexline);
    auto id = hexToBytes16(hexline);
    return {name, id};
}
