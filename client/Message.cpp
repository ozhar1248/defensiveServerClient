#include "Message.h"

Message::Message(std::string type, std::string content,
                 std::optional<int> toClient,
                 std::optional<int> fromClient,
                 std::optional<int> id)
    : id(id),
      toClient(toClient),
      fromClient(fromClient),
      type(std::move(type)),
      content(std::move(content)) {}
