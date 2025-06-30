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
        // 1. Формируем основной пакет
        std::string data_packet = MessageProtocol::build(header, client_id, msg_id, message);

        // 2. Формируем пакет с его длиной
        std::string length_str = std::to_string(data_packet.size());
        std::string length_packet = MessageProtocol::build("LENGTH", "server", -1, length_str);

        // 3. Отправляем пакет с длиной
        if (send_packet(socket, length_packet) != 0)
        {
            std::cerr << "[ERROR] [send_formatted_message] Failed to send LENGTH packet." << std::endl;
            return -1;
        }

        // Небольшая технологическая пауза. В идеальном мире она не нужна,
        // но на практике может помочь клиенту обработать пакеты по очереди.
        // Если уберете, тщательно тестируйте.
        //std::this_thread::sleep_for(std::chrono::milliseconds(20));

        // 4. Отправляем основной пакет
        if (send_packet(socket, data_packet) != 0)
        {
            std::cerr << "[ERROR] [send_formatted_message] Failed to send DATA packet." << std::endl;
            return -1;
        }

        return 0;
    }

    std::string receive_formatted_message(int socket, size_t buffer_size)
    {
        // 1. Принимаем первый пакет (ожидаем, что это пакет с длиной)
        std::string length_packet_raw = receive_packet(socket, buffer_size);
        if (length_packet_raw.empty())
            return "";

        // 2. Парсим его, чтобы узнать длину следующего пакета
        MessageProtocol::ParsedMessage parsed_length_msg;
        try
        {
            parsed_length_msg = MessageProtocol::parse(length_packet_raw);
        }
        catch (...)
        { /* ошибка парсинга */
            return "";
        }

        if (parsed_length_msg.header != "LENGTH")
        {
            // Нарушение протокола
            std::cerr << "[ERROR] [receive_formatted_message] Expected LENGTH packet, but got " << parsed_length_msg.header << std::endl;
            return "";
        }

        // !!! Этот простой recv не гарантирует получение всех данных, если они большие.
        // Здесь нужна более сложная логика чтения ровно `payload_size` байт.
        // Пока для простоты оставляем так.
        // 3. Принимаем второй, основной пакет
        std::string data_packet_raw = receive_packet(socket, buffer_size);
        if (data_packet_raw.empty())
            return "";

        // 4. Парсим его и возвращаем полезную нагрузку
        MessageProtocol::ParsedMessage parsed_data_msg;
        try
        {
            parsed_data_msg = MessageProtocol::parse(data_packet_raw);
        }
        catch (...)
        { /* ошибка парсинга */
            return "";
        }

        return parsed_data_msg.message;
    }
} // namespace ProtocolUtils