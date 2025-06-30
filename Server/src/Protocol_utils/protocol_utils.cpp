#include "protocol_utils.h"

// Системные заголовочные файлы для работы с сокетами
#include <sys/socket.h>
#include <unistd.h> // Для close()
#include <vector>
#include <iostream> // Для вывода ошибок

namespace ProtocolUtils
{

    /**
     * Реализация надежной отправки данных.
     */
    int send_packet(int socket, const std::string &data)
    {
        if (socket < 0)
        {
            std::cerr << "[ERROR] [ProtocolUtils::send_packet] Invalid socket descriptor." << std::endl;
            return -1;
        }

        const char *buffer = data.data();
        size_t total_to_send = data.size();
        size_t total_sent = 0;

        // Цикл будет продолжаться, пока все байты не будут отправлены
        while (total_sent < total_to_send)
        {
            // Пытаемся отправить оставшиеся данные.
            // MSG_NOSIGNAL предотвращает генерацию сигнала SIGPIPE, если клиент
            // внезапно закрыл соединение. Вместо этого send() вернет ошибку.
            ssize_t bytes_sent_this_call = send(socket, buffer + total_sent, total_to_send - total_sent, MSG_NOSIGNAL);

            if (bytes_sent_this_call < 0)
            {
                // Произошла ошибка сокета
                perror("[ERROR] [ProtocolUtils::send_packet] send() failed");
                return -1;
            }

            if (bytes_sent_this_call == 0)
            {
                // Это редкая ситуация, но может означать, что соединение закрыто.
                std::cerr << "[ERROR] [ProtocolUtils::send_packet] Connection closed by peer." << std::endl;
                return -1;
            }

            // Увеличиваем счетчик отправленных байт
            total_sent += bytes_sent_this_call;
        }

        return 0; // Все данные успешно отправлены
    }

    /**
     * Реализация приема данных.
     */
    std::string receive_packet(int socket, size_t buffer_size)
    {
        if (socket < 0)
        {
            std::cerr << "[ERROR] [ProtocolUtils::receive_packet] Invalid socket descriptor." << std::endl;
            return "";
        }

        // Создаем буфер для приема данных
        std::vector<char> buffer(buffer_size);

        // Пытаемся прочитать данные из сокета
        ssize_t bytes_received = recv(socket, buffer.data(), buffer.size(), 0);

        if (bytes_received < 0)
        {
            // Произошла ошибка сокета
            perror("[ERROR] [ProtocolUtils::receive_packet] recv() failed");
            return ""; // Возвращаем пустую строку при ошибке
        }

        if (bytes_received == 0)
        {
            // Это штатная ситуация, означающая, что клиент закрыл соединение
            // с его стороны (послал FIN).
            std::cout << "[INFO] [ProtocolUtils::receive_packet] Connection closed by peer (socket " << socket << ")." << std::endl;
            return ""; // Возвращаем пустую строку, сигнализируя о закрытии
        }

        // Возвращаем строку, созданную из полученных данных
        return std::string(buffer.data(), bytes_received);
    }
    int send_formatted_message(int socket, const std::string &header, const std::string &client_id, int msg_id, const std::string &message)
    {
        // 1. Формируем основной пакет с данными
        std::string data_packet = MessageProtocol::build(header, client_id, msg_id, message);

        // 2. Формируем пакет с его длиной
        std::string length_str = std::to_string(data_packet.size());
        std::string length_packet = MessageProtocol::build("LENGTH", "server", -1, length_str);

        // 3. Отправляем пакет с длиной
        if (send_packet(socket, length_packet) != 0) {
            std::cerr << "[ERROR] [send_formatted_message] Failed to send LENGTH packet." << std::endl;
            return -1;
        }

        // 4. Отправляем основной пакет с данными
        if (send_packet(socket, data_packet) != 0) {
            std::cerr << "[ERROR] [send_formatted_message] Failed to send DATA packet." << std::endl;
            return -1;
        }

        return 0;
    }
    // --- НОВОЕ: Приватная вспомогательная функция для надежного чтения ---
    namespace {
        /**
         * @brief Надежно читает ровно `bytes_to_receive` байт из сокета.
         * Блокируется, пока все байты не будут получены.
         * @return Строка с данными или пустая строка при ошибке/разрыве соединения.
         */
        std::string receive_exact_bytes(int socket, size_t bytes_to_receive) {
            std::string result;
            result.reserve(bytes_to_receive);
            
            size_t total_received = 0;
            std::vector<char> buffer(bytes_to_receive > 4096 ? 4096 : bytes_to_receive);

            while (total_received < bytes_to_receive) {
                size_t to_read_now = bytes_to_receive - total_received;
                if (to_read_now > buffer.size()) {
                    to_read_now = buffer.size();
                }

                ssize_t bytes_this_call = recv(socket, buffer.data(), to_read_now, 0);

                if (bytes_this_call <= 0) { // Ошибка или соединение закрыто
                    if (bytes_this_call < 0) {
                        perror("[ERROR] [receive_exact_bytes] recv() failed");
                    }
                    return ""; // Возвращаем пустую строку
                }

                result.append(buffer.data(), bytes_this_call);
                total_received += bytes_this_call;
            }
            return result;
        }
    }

    // --- ИЗМЕНЕНО: Полностью переписанная функция для надежного приема ---
    std::optional<MessageProtocol::ParsedMessage> receive_and_parse_message(int socket, size_t buffer_size)
    {
        // 1. Принимаем первый пакет (ожидаем, что это пакет с длиной)
        // Здесь используем старый receive_packet, т.к. мы не знаем точный размер пакета с длиной,
        // но мы знаем, что он короткий и придет целиком.
        std::string length_packet_raw = ProtocolUtils::receive_packet(socket, buffer_size);
        if (length_packet_raw.empty()) {
            return std::nullopt; // Соединение закрыто
        }

        // 2. Парсим его, чтобы узнать длину следующего пакета
        MessageProtocol::ParsedMessage parsed_length_msg;
        try {
            parsed_length_msg = MessageProtocol::parse(length_packet_raw);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] [receive_and_parse_message] Failed to parse LENGTH packet: " << e.what() << std::endl;
            return std::nullopt;
        }

        if (parsed_length_msg.header != "LENGTH") {
            std::cerr << "[ERROR] [receive_and_parse_message] Expected LENGTH packet, but got " << parsed_length_msg.header << std::endl;
            return std::nullopt;
        }

        // 3. Получаем размер основного пакета
        size_t payload_size = 0;
        try {
            payload_size = std::stoul(parsed_length_msg.message);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] [receive_and_parse_message] Invalid payload size in LENGTH packet: " << e.what() << std::endl;
            return std::nullopt;
        }

        // 4. Читаем из сокета ровно `payload_size` байт
        std::string data_packet_raw = receive_exact_bytes(socket, payload_size);
        if (data_packet_raw.empty()) {
            return std::nullopt; // Соединение закрыто во время чтения основного пакета
        }

        // 5. Парсим основной пакет и возвращаем результат
        try {
            return MessageProtocol::parse(data_packet_raw);
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] [receive_and_parse_message] Failed to parse DATA packet: " << e.what() << std::endl;
            return std::nullopt;
        }
    }
} // namespace ProtocolUtils
