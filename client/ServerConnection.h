#pragma once
#include <string>
#include <vector>   // for std::vector<uint8_t>
#include <cstdint>  // for uint8_t

// Include winsock headers (order matters on Windows)
#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

class ServerConnection {
public:
    ServerConnection(const std::string& ip, unsigned short port);
    ~ServerConnection();

    bool connectToServer();
    bool sendLine(const std::string& line);
    bool isConnected() const { return connected; }
    SOCKET getSocket() const { return sock; }

    // EXACT signatures used in main.cpp and implemented in .cpp
    bool sendAll(const uint8_t* data, int len);
    bool sendAll(const std::vector<uint8_t>& buf) {
        return sendAll(buf.data(), static_cast<int>(buf.size()));
    }
    bool recvExact(uint8_t* dst, int len);

private:
    std::string ip;
    unsigned short port;
    SOCKET sock = INVALID_SOCKET;
    bool wsaInitialized = false;
    bool connected = false;

    bool initWSA();
    void cleanupWSA();
    void closeSocket();
};
