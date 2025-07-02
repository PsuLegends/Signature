#pragma once
#include <string>
#include <optional>
#include "../Protocol/protocol.h" 

namespace ProtocolUtils {
    int send_formatted_message(int socket, const std::string& header, const std::string& client_id, int msg_id, const std::string& message);
    std::optional<MessageProtocol::ParsedMessage> receive_and_parse_message(int socket);
}