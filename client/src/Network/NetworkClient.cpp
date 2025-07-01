// Файл: Network/NetworkClient.cpp
#include "NetworkClient.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>
#include <vector>
#include "../Protocol_utils/protocol_utils.h"

// Конструктор остается прежним.
NetworkClient::NetworkClient(std::shared_ptr<logger> logger_instance, const std::string& log_path)
    : m_logger(logger_instance), m_log_path(log_path) 
{
    if (!m_logger) {
        throw std::invalid_argument("Logger instance passed to NetworkClient is null.");
    }
}

// Деструктор просто вызывает disconnect.
NetworkClient::~NetworkClient() {
    disconnect();
}

bool NetworkClient::is_connected() const {
    return m_socket != -1;
}

// connect остается почти без изменений.
bool NetworkClient::connect(const std::string& ip, uint16_t port) {
    m_logger->write_log(m_log_path, "[Network] Попытка подключения к " + ip + ":" + std::to_string(port));
    
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket < 0) { 
        m_logger->write_log(m_log_path, "[Network] Ошибка создания сокета: " + std::string(strerror(errno)));
        return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        m_logger->write_log(m_log_path, "[Network] Ошибка: неверный IP адрес " + ip);
        disconnect();
        return false;
    }
    
    if (::connect(m_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        m_logger->write_log(m_log_path, "[Network] Ошибка подключения к серверу: " + std::string(strerror(errno)));
        disconnect();
        return false;
    }
    
    auto welcome_msg = receive();
    if (!welcome_msg) {
        m_logger->write_log(m_log_path, "[Network] Сервер не прислал приветственное сообщение или соединение было сброшено.");
        return false;
    }

    if (welcome_msg->header == "CONN_REJECT") {
         m_logger->write_log(m_log_path, "[Network] Отказ в соединении: " + welcome_msg->message);
         disconnect(); // После отказа сервер сам закроет соединение, но мы тоже это делаем.
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


// Упрощаем disconnect. Он только закрывает сокет.
void NetworkClient::disconnect() {
    if (is_connected()) {
        m_logger->write_log(m_log_path, "[Network] Закрытие сокета.");
        ::close(m_socket);
        m_socket = -1;
    }
}

// Упрощаем send. Он только отправляет и возвращает результат.
// Он больше не вызывает disconnect(). Решение об этом принимает AppLogic.
bool NetworkClient::send(const MessageProtocol::ParsedMessage& msg) {
    if (!is_connected()) {
        m_logger->write_log(m_log_path, "[Network] Ошибка отправки: нет активного соединения.");
        return false;
    }
    
    m_logger->write_log(m_log_path, "[Network] -> Отправка сообщения. Заголовок: " + msg.header);
    
    if (ProtocolUtils::send_formatted_message(m_socket, msg.header, msg.clientID, msg.messageID, msg.message) != 0) {
        m_logger->write_log(m_log_path, "[Network] Ошибка при отправке сообщения. Вероятно, соединение потеряно.");
        return false; // Просто возвращаем false.
    }
    return true;
}


// Логика receive и try_parse_message_from_buffer остается той же, что в прошлый раз,
// так как она решала проблему "слипшихся" пакетов. Я просто продублирую ее здесь для полноты.

std::optional<MessageProtocol::ParsedMessage> NetworkClient::receive() {
    auto parsed_message = try_parse_message_from_buffer();
    if (parsed_message) {
        m_logger->write_log(m_log_path, "[Network] Сообщение извлечено из существующего буфера.");
        return parsed_message;
    }
    std::vector<char> temp_buffer(4096);
    while (true) {
        ssize_t bytes_received = recv(m_socket, temp_buffer.data(), temp_buffer.size(), 0);
        if (bytes_received > 0) {
            m_receive_buffer.append(temp_buffer.data(), bytes_received);
            parsed_message = try_parse_message_from_buffer();
            if (parsed_message) return parsed_message;
        } else {
            if (bytes_received == 0) m_logger->write_log(m_log_path, "[Network] Соединение закрыто сервером.");
            else m_logger->write_log(m_log_path, "[Network] Ошибка recv(): " + std::string(strerror(errno)));
            disconnect();
            return std::nullopt;
        }
    }
}

std::optional<MessageProtocol::ParsedMessage> NetworkClient::try_parse_message_from_buffer() {
    size_t first_delim = m_receive_buffer.find('\n');
    if (first_delim == std::string::npos) return std::nullopt;
    
    std::string length_packet_raw = m_receive_buffer.substr(0, first_delim + 1);
    
    MessageProtocol::ParsedMessage parsed_length_msg;
    try {
        parsed_length_msg = MessageProtocol::parse(length_packet_raw);
    } catch (...) { return std::nullopt; }
    
    if (parsed_length_msg.header != "LENGTH") {
        m_logger->write_log(m_log_path, "[Network] Ошибка протокола: ожидали LENGTH, получили " + parsed_length_msg.header);
        return std::nullopt;
    }
    
    size_t payload_size = 0;
    try {
        payload_size = std::stoul(parsed_length_msg.message);
    } catch (...) { return std::nullopt; }
    
    size_t total_expected_size = length_packet_raw.size() + payload_size;
    if (m_receive_buffer.size() < total_expected_size) return std::nullopt;
    
    std::string data_packet_raw = m_receive_buffer.substr(length_packet_raw.size(), payload_size);
    m_receive_buffer.erase(0, total_expected_size);
    
    try {
        auto final_msg = MessageProtocol::parse(data_packet_raw);
        m_logger->write_log(m_log_path, "[Network] <- Получено и распарсено сообщение. Заголовок: " + final_msg.header);
        return final_msg;
    } catch(...) { return std::nullopt; }
}