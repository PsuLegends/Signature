#include "protocol.h"
#include <random>
#include <sstream>

std::string MessageProtocol::build(const std::string& header,
                                   const std::string& clientID,
                                   int messageID,
                                   const std::string& messageBody) {
    return header + "|clientID:" + clientID +
           "|messageID:" + std::to_string(messageID) +
           "|message:" + messageBody+"\n";
}
MessageProtocol::ParsedMessage MessageProtocol::parse(const std::string& raw) {
    std::mutex mtx;
    mtx.lock();
    ParsedMessage result;
    size_t pos = 0;
    size_t next = raw.find('|');

    if (next == std::string::npos)
        return result;
    result.header = raw.substr(0, next);
    pos = next + 1;

    while ((next = raw.find('|', pos)) != std::string::npos) {
        std::string part = raw.substr(pos, next - pos);
        if (part.rfind("clientID:", 0) == 0) {
            result.clientID = part.substr(9);
        } else if (part.rfind("messageID:", 0) == 0) {
            try {
                result.messageID = std::stoi(part.substr(10));
            } catch (...) {
                result.messageID = -1;
            }
        }
        pos = next + 1;
    }

    std::string last = raw.substr(pos);
    if (last.rfind("message:", 0) == 0) {
        result.message = last.substr(8);
        result.message.pop_back();
    }
    mtx.unlock();
    return result;
}

int MessageProtocol::generateMessageID() {
    static std::mt19937 gen(std::random_device{}());
    static std::uniform_int_distribution<> dist(1, 32);
    return dist(gen);
}
