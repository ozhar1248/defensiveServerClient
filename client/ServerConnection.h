#pragma once
#include <string>

// Include winsock headers (order matters on Windows)
#include <winsock2.h>
#include <ws2tcpip.h>

#ifdef _MSC_VER
// Only MSVC understands this pragma; MinGW will ignore it otherwise.
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
