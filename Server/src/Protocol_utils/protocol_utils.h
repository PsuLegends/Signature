// Файл: Protocol_utils/protocol_utils.h (остается без изменений)
#pragma once

#include <string>
#include <optional>
#include "../Protocol/protocol.h" 

namespace ProtocolUtils {

    /**
     * @brief Высокоуровневая функция для отправки сообщения по протоколу.
     * @details (Внутренняя реализация теперь использует 4 байта длины + тело).
     * @return 0 в случае успеха, -1 в случае ошибки.
     */
    int send_formatted_message(int socket, const std::string& header, const std::string& client_id, int msg_id, const std::string& message);

    /**
     * @brief Высокоуровневая функция для приема сообщения по протоколу.
     * @details (Внутренняя реализация теперь использует 4 байта длины + тело).
     * @return Распарсированная полезная нагрузка. std::nullopt при ошибке.
     */
    std::optional<MessageProtocol::ParsedMessage> receive_and_parse_message(int socket);

    // Старые send_packet/receive_packet можно оставить как приватные или удалить,
    // если они больше нигде не используются напрямую. Для чистоты лучше убрать.
}