// main.cpp
#include "ServerConnection.h"
#include "FileConfig.h"
#include <iostream>
#include <string>
#include <winsock2.h>

int main() {
    std::string ip;
    unsigned short port;

    try {
        auto cfg = FileConfig::readServerInfo();
        ip = cfg.first;
        port = cfg.second;
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
    std::cout << "Type messages to send. Type 'quit' to exit.\n";

    std::string line;
    char buffer[4096];

    while (true) {
        std::cout << "what would you like to send? ";
        if (!std::getline(std::cin, line)) break;
        if (line == "quit") break;

        if (!conn.sendLine(line)) {
            std::cerr << "Failed to send. Connection closed.\n";
            break;
        }

        int received = recv(conn.getSocket(), buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            buffer[received] = '\0';
            std::cout << "Server: " << buffer;
        } else if (received == 0) {
            std::cout << "Server closed connection.\n";
            break;
        } else {
            std::cerr << "recv() failed: " << WSAGetLastError() << "\n";
            break;
        }
    }

    std::cout << "Client exiting.\n";
    return 0;
}
