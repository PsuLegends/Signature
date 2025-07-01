// Файл: Network/NetworkClient.h
#pragma once
#include <string>
#include <optional>
#include <memory>
#include "../Protocol/protocol.h"
#include "../Logger/logger.h"

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
    
    // Интерфейс остается тем же!
    std::optional<MessageProtocol::ParsedMessage> receive();

private:
    // НОВОЕ: Внутренний буфер для данных, "перечитанных" из сокета.
    std::string m_receive_buffer;
    
    // Вспомогательный приватный метод для парсинга
    std::optional<MessageProtocol::ParsedMessage> try_parse_message_from_buffer();

    int m_socket = -1;
    std::shared_ptr<logger> m_logger;
    std::string m_log_path;
};