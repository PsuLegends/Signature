#pragma once
#include <string>
#include <mutex>
class MessageProtocol {
public:
    struct ParsedMessage {
        std::string header;
        std::string clientID;
        int messageID = -1;
        std::string message;
    };

    static std::string build(const std::string& header,
                             const std::string& clientID,
                             int messageID,
                             const std::string& messageBody);

    static ParsedMessage parse(const std::string& raw);
    static int generateMessageID();
};
