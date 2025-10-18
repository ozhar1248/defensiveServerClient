// FileConfig.cpp
#include "FileConfig.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <stdexcept>

using namespace std;

static filesystem::path exeDir() {
    char buf[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    filesystem::path p(string(buf, n));
    return p.parent_path();
}

pair<string, unsigned short> FileConfig::readServerInfo() {
    auto path = exeDir() / "server.info";
    if (!filesystem::exists(path)) {
        throw runtime_error("server.info not found at: " + path.string());
    }

    ifstream in(path);
    string line;
    getline(in, line); // assume valid format "IP:PORT"
    // parse
    auto pos = line.find(':');
    string ip = line.substr(0, pos);
    unsigned short port = static_cast<unsigned short>(stoi(line.substr(pos + 1)));
    return { ip, port };
}
