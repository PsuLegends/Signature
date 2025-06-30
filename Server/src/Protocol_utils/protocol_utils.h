#pragma once

#include <string>
#include "../Protocol/protocol.h" // Нужен для MessageProtocol::build/parse

/**
 * @brief Пространство имен для утилит, связанных с низкоуровневой передачей данных по протоколу.
 */
namespace ProtocolUtils {

    /**
     * @brief Надежно отправляет пакет данных в сокет.
     * Гарантирует, что все данные будут отправлены, даже если системный вызов
     * send() отправит их по частям.
     * @param socket Дескриптор сокета клиента.
     * @param data Данные для отправки.
     * @return 0 в случае успеха, -1 в случае ошибки (например, разрыв соединения).
     */
    int send_packet(int socket, const std::string& data);

    /**
     * @brief Принимает пакет данных из сокета.
     * Читает данные из сокета до тех пор, пока они есть, но не более чем buffer_size.
     * @param socket Дескриптор сокета клиента.
     * @param buffer_size Максимальный размер данных для чтения за один вызов.
     * @return Полученные данные в виде строки. Если произошла ошибка или
     *         соединение закрыто, возвращает пустую строку.
     */
    std::string receive_packet(int socket, size_t buffer_size);
    /**
     * @brief Высокоуровневая функция для отправки сообщения по протоколу LENGTH + DATA.
     * Сначала формирует и отправляет пакет с длиной, а затем - основной пакет с данными.
     * @return 0 в случае успеха, -1 в случае ошибки.
     */
    int send_formatted_message(int socket, const std::string& header, const std::string& client_id, int msg_id, const std::string& message);

    /**
     * @brief Высокоуровневая функция для приема сообщения по протоколу LENGTH + DATA.
     * Сначала принимает и парсит пакет с длиной, а затем принимает основной пакет.
     * @return Распарсированная полезная нагрузка (message). Пустая строка при ошибке.
     */
    std::string receive_formatted_message(int socket, size_t buffer_size);

} // namespace ProtocolUtils