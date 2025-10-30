#include "FileConfig.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#include <osrng.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/queue.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/secblock.h>

using namespace std;
namespace fs = std::filesystem;

// helper: exe dir
static fs::path exeDir() {
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return fs::path(string(buf, n)).parent_path();
}

// existing server.info loader (unchanged)
std::pair<std::string, unsigned short> FileConfig::readServerInfo() {
    auto path = exeDir() / "server.info";
    if (!fs::exists(path)) {
        throw runtime_error("server.info not found at: " + path.string());
    }
    ifstream in(path);
    string line; getline(in, line); // IP:PORT
    size_t pos = line.find(':');
    string ip = line.substr(0, pos);
    unsigned short port = static_cast<unsigned short>(stoi(line.substr(pos + 1)));
    return { ip, port };
}

// Helper: hex (16 bytes) -> hex string (32 chars)
static string bytes16ToHex(const array<uint8_t,16>& a) {
    ostringstream ss;
    ss << hex << setfill('0');
    for (auto b : a) ss << setw(2) << static_cast<int>(b);
    return ss.str();
}
static array<uint8_t,16> hexToBytes16(const string& hex) {
    if (hex.size() < 32) throw runtime_error("UUID hex too short");
    array<uint8_t,16> out{};
    for (size_t i = 0; i < 16; ++i) {
        unsigned int v;
        std::istringstream iss(hex.substr(2*i,2));
        iss >> std::hex >> v;
        out[i] = static_cast<uint8_t>(v & 0xFF);
    }
    return out;
}

// Read full my.info (username, id, base64 private key)
std::tuple<std::string, std::array<uint8_t,16>, std::string>
FileConfig::readFullMyInfo() {
    auto path = exeDir() / "my.info";
    if (!fs::exists(path)) {
        throw runtime_error("my.info not found at: " + path.string());
    }
    ifstream in(path);
    string username, hexline, base64pk;
    if (!getline(in, username)) throw runtime_error("my.info malformed (no username)");
    if (!getline(in, hexline))  throw runtime_error("my.info malformed (no id)");
    if (!getline(in, base64pk)) base64pk = "";
    auto id = hexToBytes16(hexline);
    return { username, id, base64pk };
}

// write my.info
void FileConfig::writeMyInfo(const string& username,
                             const array<uint8_t,16>& clientId,
                             const string& privateKeyBase64)
{
    auto path = exeDir() / "my.info";
    ofstream out(path, ios::binary | ios::trunc);
    if (!out) throw runtime_error("failed to open my.info for writing");
    out << username << "\n";
    out << bytes16ToHex(clientId) << "\n";
    out << privateKeyBase64 << "\n";
    out.close();
}

// generate RSA 1024 private key, base64-encode DER, write file, return base64
string FileConfig::generateAndSavePrivateKey(const string& username,
                                             const array<uint8_t,16>& clientId)
{
    auto path = exeDir() / "my.info";
    if (fs::exists(path)) {
        throw runtime_error("my.info already exists; refusing to overwrite");
    }

    // Generate RSA 1024 key
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024);
    CryptoPP::RSA::PrivateKey privateKey(params);

    // DER encode private key to a ByteQueue
    CryptoPP::ByteQueue queue;
    privateKey.DEREncodePrivateKey(queue);

    // Base64-encode DER
    std::string base64;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(base64), false);
    queue.CopyTo(encoder);
    encoder.MessageEnd();

    // Write my.info
    writeMyInfo(username, clientId, base64);

    return base64;
}

bool FileConfig::myInfoExists() {
    auto path = exeDir() / "my.info";
    return std::filesystem::exists(path);
}


