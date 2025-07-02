#include "protocol_utils.h"
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <iostream>
#include <arpa/inet.h> 
#include <stdexcept>

namespace ProtocolUtils {

    namespace {
        int send_all(int socket, const char* buffer, size_t length) {
            size_t total_sent = 0;
            while (total_sent < length) {
                ssize_t sent_now = ::send(socket, buffer + total_sent, length - total_sent, MSG_NOSIGNAL);
                if (sent_now <= 0) {
                    perror("send_all failed");
                    return -1; 
                }
                total_sent += sent_now;
            }
            return 0; 
        }
        std::string receive_all(int socket, size_t bytes_to_receive) {
            if (bytes_to_receive == 0) return "";
            
            std::string buffer(bytes_to_receive, '\0');
            ssize_t bytes_read = ::recv(socket, &buffer[0], bytes_to_receive, MSG_WAITALL);
            
            if (bytes_read != static_cast<ssize_t>(bytes_to_receive)) {
                return "";
            }
            
            return buffer;
        }

    } 
    int send_formatted_message(int socket, const std::string& header, const std::string& client_id, int msg_id, const std::string& message) {
        std::string body = MessageProtocol::build(header, client_id, msg_id, message);
        uint32_t len = body.length();
        uint32_t network_len = htonl(len); 
        if (send_all(socket, reinterpret_cast<const char*>(&network_len), sizeof(network_len)) != 0) {
            std::cerr << "[ProtocolUtils] Ошибка отправки длины сообщения." << std::endl;
            return -1;
        }
        if (send_all(socket, body.data(), body.size()) != 0) {
            std::cerr << "[ProtocolUtils] Ошибка отправки тела сообщения." << std::endl;
            return -1;
        }

        return 0;
    }
    

    std::optional<MessageProtocol::ParsedMessage> receive_and_parse_message(int socket) {
        uint32_t network_len = 0;
        std::string len_bytes = receive_all(socket, sizeof(network_len));
        if (len_bytes.size() != sizeof(network_len)) {
            return std::nullopt;
        }
        network_len = *reinterpret_cast<const uint32_t*>(len_bytes.data());
        uint32_t body_len = ntohl(network_len);
        const size_t MAX_MSG_SIZE = 1024 * 1024;
        if (body_len > MAX_MSG_SIZE) {
            std::cerr << "[ProtocolUtils] Ошибка: получена слишком большая длина сообщения: " << body_len << std::endl;
            return std::nullopt;
        }
        std::string body = receive_all(socket, body_len);
        if (body.size() != body_len) {
            return std::nullopt;
        }
        try {
            return MessageProtocol::parse(body);
        } catch (const std::exception& e) {
            std::cerr << "[ProtocolUtils] Ошибка парсинга тела сообщения: " << e.what() << std::endl;
            return std::nullopt;
        }
    }

}