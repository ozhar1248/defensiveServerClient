#include "ServerConnection.h"
#include <iostream>

bool ServerConnection::initWSA() {
    WSADATA wsaData;
    int r = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (r != 0) {
        std::cerr << "WSAStartup failed: " << r << "\n";
        return false;
    }
    return true;
}

void ServerConnection::cleanupWSA() {
    if (wsaInitialized) {
        WSACleanup();
        wsaInitialized = false;
    }
}

void ServerConnection::closeSocket() {
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
        sock = INVALID_SOCKET;
    }
    connected = false;
}

ServerConnection::ServerConnection(const std::string& ip, unsigned short port)
    : ip(ip), port(port) {
    wsaInitialized = initWSA();
}

ServerConnection::~ServerConnection() {
    closeSocket();
    cleanupWSA();
}

bool ServerConnection::connectToServer() {
    if (!wsaInitialized) return false;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "socket() failed: " << WSAGetLastError() << "\n";
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        std::cerr << "inet_pton failed for IP: " << ip << "\n";
        closeSocket();
        return false;
    }

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "connect() failed: " << WSAGetLastError() << "\n";
        closeSocket();
        return false;
    }

    connected = true;
    return true;
}

bool ServerConnection::sendLine(const std::string& line) {
    if (!connected || sock == INVALID_SOCKET) return false;

    std::string payload = line;
    payload += "\n";

    const char* buf = payload.c_str();
    int toSend = static_cast<int>(payload.size());
    int totalSent = 0;

    while (totalSent < toSend) {
        int sent = send(sock, buf + totalSent, toSend - totalSent, 0);
        if (sent == SOCKET_ERROR) {
            std::cerr << "send() failed: " << WSAGetLastError() << "\n";
            closeSocket();
            return false;
        }
        totalSent += sent;
    }
    return true;
}
