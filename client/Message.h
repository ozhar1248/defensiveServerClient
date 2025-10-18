#pragma once
#include <string>
#include <optional>

class Message {
public:
    // Fields mirror server table (ID may be unknown on the client side)
    std::optional<int> id;
    std::optional<int> toClient;
    std::optional<int> fromClient;
    std::string type;
    std::string content;

    Message(std::string type, std::string content,
            std::optional<int> toClient = std::nullopt,
            std::optional<int> fromClient = std::nullopt,
            std::optional<int> id = std::nullopt);

    // later we can add encode()/decode() if we choose a wire protocol
};
