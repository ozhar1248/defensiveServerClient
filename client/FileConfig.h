
#pragma once
#include <string>
#include <utility>
#include <tuple>
#include <array>
#include <cstdint>

// This class provides file I/O utilities for reading and writing configuration

class FileConfig
{
public:
    // ------------------------------------------------------------------------
    // Reads server connection info from "server.info".
    // Expected format:
    //   <server-address>
    //   <port>
    //
    // Returns: { serverAddress, portNumber }
    // Throws or returns empty data if file not found or invalid.
    // ------------------------------------------------------------------------
    static std::pair<std::string, unsigned short> readServerInfo();
    
    // ------------------------------------------------------------------------
    // Reads full client info from "my.info".
    // Expected format (example):
    //   username
    //   <16-byte binary clientId>
    //   <Base64-encoded private key>
    //
    // Returns: (username, clientId[16], privateKeyBase64)
    // ------------------------------------------------------------------------
    static std::tuple<std::string, std::array<uint8_t, 16>, std::string> readFullMyInfo();
    
    // ------------------------------------------------------------------------
    // Writes "my.info" file with the given user information.
    //
    // Parameters:
    //   username      - ASCII name of the client
    //   clientId      - 16-byte UUID assigned by the server
    //   privateKeyB64 - Base64-encoded RSA private key
    //
    // Overwrites existing file if present.
    // ------------------------------------------------------------------------
    static void writeMyInfo(const std::string &, const std::array<uint8_t, 16> &, const std::string &);
    
    // ------------------------------------------------------------------------
    // Generates a new RSA private key (using Encryption::GenerateRsaKeypair1024)
    // and saves it into "my.info" together with username and clientId.
    //
    // Throws or returns an error if the file already exists to avoid overwriting
    // an existing identity.
    //
    // Returns: Base64-encoded private key string.
    // ------------------------------------------------------------------------
    static std::string generateAndSavePrivateKey(const std::string &, const std::array<uint8_t, 16> &);
    
    // ------------------------------------------------------------------------
    // Checks whether "my.info" already exists in the current directory.
    // Useful for determining whether the client has been registered before.
    //
    // Returns: true if the file exists, false otherwise.
    // ------------------------------------------------------------------------
    static bool myInfoExists();
};
