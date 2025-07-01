// Файл: Network/NetworkClient.h
#pragma once

#include <string>
#include <optional>
#include <memory> // для std::shared_ptr

// Зависимости от ваших существующих модулей
#include "../Protocol/protocol.h"
#include "../Logger/logger.h" // Для внедрения зависимости логгера

class NetworkClient {
public:
    NetworkClient(std::shared_ptr<logger> logger_instance, const std::string& log_path);
    ~NetworkClient();
    NetworkClient(const NetworkClient&) = delete;
    NetworkClient& operator=(const NetworkClient&) = delete;
    bool connect(const std::string& ip, uint16_t port);
    void disconnect();
    bool is_connected() const;
    bool send(const MessageProtocol::ParsedMessage& msg);
    std::optional<MessageProtocol::ParsedMessage> receive();

private:
    int m_socket = -1;
    std::shared_ptr<logger> m_logger;
    std::string m_log_path;
};