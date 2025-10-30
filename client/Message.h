#pragma once
#include <vector>    
#include <array>     
#include <cstdint>
#include <string>
#include <optional>

class Message {
public:
    std::optional<int> id;
    std::optional<int> toClient;
    std::optional<int> fromClient;
    std::string type;
    std::string content;

    Message(std::string type, std::string content,
            std::optional<int> toClient = std::nullopt,
            std::optional<int> fromClient = std::nullopt,
            std::optional<int> id = std::nullopt);

};

struct MessageEnvelope {
    std::array<uint8_t,16> fromId;
    uint32_t id;
    uint8_t type; 
    std::vector<uint8_t> content;
    static const char* typeName(uint8_t t) {
        switch(t){case 1: return "Request for symmetric key";
                   case 2: return "Symmetric key";
                   case 3: return "Text";
                   default: return "Unknown";}
    }
};
