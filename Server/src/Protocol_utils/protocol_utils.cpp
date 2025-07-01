// Файл: Protocol_utils/protocol_utils.cpp (НОВАЯ РЕАЛИЗАЦИЯ)

#include "protocol_utils.h"

// Необходимые системные заголовочные файлы
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <arpa/inet.h> // Для htonl, ntohl
#include <stdexcept>

namespace ProtocolUtils {

    // --- Приватные вспомогательные функции (они теперь основа) ---
    namespace {

        /**
         * @brief Надежно отправляет весь буфер данных в сокет.
         */
        int send_all(int socket, const char* buffer, size_t length) {
            size_t total_sent = 0;
            while (total_sent < length) {
                ssize_t sent_now = ::send(socket, buffer + total_sent, length - total_sent, MSG_NOSIGNAL);
                if (sent_now <= 0) {
                    perror("send_all failed");
                    return -1; // Ошибка или разрыв соединения
                }
                total_sent += sent_now;
            }
            return 0; // Успех
        }

        /**
         * @brief Надежно читает ровно `bytes_to_receive` байт из сокета.
         * Использует MSG_WAITALL для эффективности.
         * @return Строка с данными или пустая строка при ошибке/разрыве соединения.
         */
        std::string receive_all(int socket, size_t bytes_to_receive) {
            if (bytes_to_receive == 0) return "";
            
            std::string buffer(bytes_to_receive, '\0');
            ssize_t bytes_read = ::recv(socket, &buffer[0], bytes_to_receive, MSG_WAITALL);
            
            if (bytes_read != static_cast<ssize_t>(bytes_to_receive)) {
                // Если мы не получили ровно столько, сколько просили, это ошибка или разрыв.
                return "";
            }
            
            return buffer;
        }

    } // конец анонимного namespace

    // --- Реализация публичных функций с НОВОЙ логикой ---

    int send_formatted_message(int socket, const std::string& header, const std::string& client_id, int msg_id, const std::string& message) {
        // 1. Формируем тело сообщения (как и раньше)
        std::string body = MessageProtocol::build(header, client_id, msg_id, message);
        
        // 2. Получаем его длину и конвертируем в 4-байтовое сетевое число
        uint32_t len = body.length();
        uint32_t network_len = htonl(len); // Host-To-Network-Long
        
        // 3. Отправляем 4 байта с длиной
        if (send_all(socket, reinterpret_cast<const char*>(&network_len), sizeof(network_len)) != 0) {
            std::cerr << "[ProtocolUtils] Ошибка отправки длины сообщения." << std::endl;
            return -1;
        }

        // 4. Отправляем само тело сообщения
        if (send_all(socket, body.data(), body.size()) != 0) {
            std::cerr << "[ProtocolUtils] Ошибка отправки тела сообщения." << std::endl;
            return -1;
        }

        return 0; // Успех
    }
    

    std::optional<MessageProtocol::ParsedMessage> receive_and_parse_message(int socket) {
        // 1. Читаем ровно 4 байта, чтобы узнать длину
        uint32_t network_len = 0;
        std::string len_bytes = receive_all(socket, sizeof(network_len));
        if (len_bytes.size() != sizeof(network_len)) {
            // Соединение разорвано
            return std::nullopt;
        }
        network_len = *reinterpret_cast<const uint32_t*>(len_bytes.data());

        // 2. Конвертируем из сетевого порядка в хостовый
        uint32_t body_len = ntohl(network_len);
        
        // Проверка на адекватность размера (защита от DoS-атак с огромным размером)
        const size_t MAX_MSG_SIZE = 1024 * 1024; // 1 MB, например
        if (body_len > MAX_MSG_SIZE) {
            std::cerr << "[ProtocolUtils] Ошибка: получена слишком большая длина сообщения: " << body_len << std::endl;
            return std::nullopt;
        }

        // 3. Читаем ровно `body_len` байт тела сообщения
        std::string body = receive_all(socket, body_len);
        if (body.size() != body_len) {
            // Соединение разорвано при чтении тела
            return std::nullopt;
        }

        // 4. Парсим тело и возвращаем
        try {
            return MessageProtocol::parse(body);
        } catch (const std::exception& e) {
            std::cerr << "[ProtocolUtils] Ошибка парсинга тела сообщения: " << e.what() << std::endl;
            return std::nullopt;
        }
    }

} // namespace ProtocolUtils