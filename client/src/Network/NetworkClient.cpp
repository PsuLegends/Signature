// Файл: Network/NetworkClient.cpp
#include "NetworkClient.h"

// Системные заголовочные файлы для работы с сокетами
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h> // для close()
#include <stdexcept> // для исключений

// Включаем ваши утилиты для работы с протоколом
#include "../Protocol_utils/protocol_utils.h"

NetworkClient::NetworkClient(std::shared_ptr<logger> logger_instance, const std::string& log_path)
    : m_logger(logger_instance), m_log_path(log_path) {
    if (!m_logger) {
        throw std::invalid_argument("Logger instance cannot be null.");
    }
}

NetworkClient::~NetworkClient() {
    disconnect();
}

bool NetworkClient::connect(const std::string& ip, uint16_t port) {
    m_logger->write_log(m_log_path, "[Network] Попытка подключения к " + ip + ":" + std::to_string(port));
    
    // 1. Создание сокета (ваш код из client::start)
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket < 0) {
        m_logger->write_log(m_log_path, "[Network] Ошибка: не удалось создать сокет.");
        perror("socket"); // Вывод системной ошибки
        return false;
    }

    // 2. Настройка адреса сервера (ваш код из client::start)
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        m_logger->write_log(m_log_path, "[Network] Ошибка: неверный IP адрес " + ip);
        disconnect();
        return false;
    }

    // 3. Установка соединения (ваш код из client::connect_to_server)
    if (::connect(m_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        m_logger->write_log(m_log_path, "[Network] Ошибка: не удалось подключиться к серверу.");
        perror("connect");
        disconnect();
        return false;
    }

    // 4. КЛЮЧЕВОЙ ШАГ: Ожидание подтверждения от сервера.
    // Ваш сервер после accept немедленно отправляет CONN_ACCEPT. Мы должны его получить.
    auto welcome_msg = receive();
    if (!welcome_msg) {
        m_logger->write_log(m_log_path, "[Network] Ошибка: сервер не прислал приветственное сообщение.");
        disconnect();
        return false;
    }
    
    if (welcome_msg->header == "CONN_REJECT") {
         m_logger->write_log(m_log_path, "[Network] Отказ в соединении: " + welcome_msg->message);
         disconnect();
         return false;
    }
    
    if (welcome_msg->header != "CONN_ACCEPT") {
        m_logger->write_log(m_log_path, "[Network] Ошибка: получено некорректное приветствие: " + welcome_msg->header);
        disconnect();
        return false;
    }

    m_logger->write_log(m_log_path, "[Network] Соединение с сервером успешно установлено.");
    return true;
}

void NetworkClient::disconnect() {
    if (m_socket != -1) {
        m_logger->write_log(m_log_path, "[Network] Закрытие сокета.");
        ::close(m_socket);
        m_socket = -1;
    }
}

bool NetworkClient::is_connected() const {
    return m_socket != -1;
}

// Этот метод становится простой оберткой над вашей утилитой
bool NetworkClient::send(const MessageProtocol::ParsedMessage& msg) {
    if (!is_connected()) {
        m_logger->write_log(m_log_path, "[Network] Ошибка отправки: нет активного соединения.");
        return false;
    }
    
    m_logger->write_log(m_log_path, "[Network] -> Отправка сообщения. Заголовок: " + msg.header);
    
    // Используем вашу готовую функцию!
    if (ProtocolUtils::send_formatted_message(m_socket, msg.header, msg.clientID, msg.messageID, msg.message) != 0) {
        m_logger->write_log(m_log_path, "[Network] Ошибка при отправке сообщения.");
        // В случае ошибки отправки соединение, скорее всего, потеряно.
        disconnect();
        return false;
    }
    return true;
}

// Этот метод также становится простой оберткой
std::optional<MessageProtocol::ParsedMessage> NetworkClient::receive() {
    if (!is_connected()) {
        m_logger->write_log(m_log_path, "[Network] Ошибка приема: нет активного соединения.");
        return std::nullopt;
    }
    
    // Используем вашу готовую надежную функцию!
    auto received_data = ProtocolUtils::receive_and_parse_message(m_socket);

    if (received_data) {
        m_logger->write_log(m_log_path, "[Network] <- Получено сообщение. Заголовок: " + received_data->header);
    } else {
        // receive_and_parse_message уже логирует разрыв соединения, но мы можем добавить свое
        m_logger->write_log(m_log_path, "[Network] Соединение разорвано или произошла ошибка при приеме.");
        disconnect();
    }
    
    return received_data;
}