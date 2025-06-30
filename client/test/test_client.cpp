#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <mutex>
#include <thread>
#include <chrono>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

// --- Начало: Модуль Протокола ---
class MessageProtocol {
public:
    struct ParsedMessage {
        std::string header;
        std::string clientID;
        int messageID = -1;
        std::string message;
    };

    static std::string build(const std::string& header, const std::string& clientID, int messageID, const std::string& messageBody) {
        return header + "|clientID:" + clientID + "|messageID:" + std::to_string(messageID) + "|message:" + messageBody + "\n";
    }

    static ParsedMessage parse(const std::string& raw_input) {
        ParsedMessage result;
        if (raw_input.empty()) return result;

        size_t end_of_message = raw_input.find('\n');
        std::string raw = (end_of_message == std::string::npos) ? raw_input : raw_input.substr(0, end_of_message);

        size_t pos = 0;
        size_t next = raw.find('|');

        if (next == std::string::npos) {
            result.header = raw;
            result.message = raw;
            return result;
        }

        result.header = raw.substr(0, next);
        pos = next + 1;

        while (pos < raw.length()) {
            next = raw.find('|', pos);
            if (next == std::string::npos) {
                 next = raw.length();
            }
            
            std::string part = raw.substr(pos, next - pos);
            size_t colon_pos = part.find(':');
            if (colon_pos != std::string::npos) {
                std::string key = part.substr(0, colon_pos);
                std::string value = part.substr(colon_pos + 1);
                
                if (key == "clientID") {
                    result.clientID = value;
                } else if (key == "messageID") {
                    try { result.messageID = std::stoi(value); } catch (...) { result.messageID = -1; }
                } else if (key == "message") {
                    result.message = value;
                }
            }
            pos = next + 1;
        }
        return result;
    }
};
// --- Конец: Модуль Протокола ---


// --- Начало: Модуль Крипто-утилит ---
namespace CryptoUtils {
    std::string generate_hash(const std::string& input) {
        CryptoPP::SHA256 hash_algorithm;
        std::string digest;
        CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size(), true,
            new CryptoPP::HashFilter(hash_algorithm,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest)
                )
            )
        );
        return digest;
    }
}
// --- Конец: Модуль Крипто-утилит ---


// --- Начало: Класс Клиента ---
class Client {
public:
    Client(const std::string& ip, uint16_t port, const std::string& user, const std::string& pass);
    ~Client();

    bool run_registration();
    bool run_interactive_session(); // ИЗМЕНЕНО

private:
    bool connect_to_server();
    void disconnect();
    bool send_packet(const std::string& data);
    
    std::string get_one_message_from_socket();
    MessageProtocol::ParsedMessage receive_formatted_packet();

    bool handle_initial_connection();
    bool handle_authentication();
    void handle_signing();
    void handle_get_public_key();

    std::string server_ip;
    uint16_t server_port;
    std::string username;
    std::string password;
    int socket_fd = -1;
    std::string receive_buffer;
};

Client::Client(const std::string& ip, uint16_t port, const std::string& user, const std::string& pass)
    : server_ip(ip), server_port(port), username(user), password(pass) {}

Client::~Client() {
    disconnect();
}

std::string Client::get_one_message_from_socket() {
    size_t end_pos;
    while ((end_pos = receive_buffer.find('\n')) == std::string::npos) {
        char chunk[4096];
        ssize_t bytes_read = recv(socket_fd, chunk, sizeof(chunk), 0);
        if (bytes_read <= 0) {
            if (bytes_read < 0) perror("recv");
            else std::cout << "[INFO] Сервер закрыл соединение." << std::endl;
            disconnect();
            return "";
        }
        receive_buffer.append(chunk, bytes_read);
    }
    
    std::string message = receive_buffer.substr(0, end_pos + 1);
    receive_buffer.erase(0, end_pos + 1);
    return message;
}

MessageProtocol::ParsedMessage Client::receive_formatted_packet() {
    std::string length_packet_raw = get_one_message_from_socket();
    if (length_packet_raw.empty()) return {};

    auto len_msg = MessageProtocol::parse(length_packet_raw);
    if (len_msg.header != "LENGTH") {
        std::cerr << "[ERROR] Ожидался пакет LENGTH, но получен '" << len_msg.header << "'" << std::endl;
        return len_msg;
    }

    std::string data_packet_raw = get_one_message_from_socket();
    if (data_packet_raw.empty()) return {};

    return MessageProtocol::parse(data_packet_raw);
}

bool Client::run_registration() {
    if (!connect_to_server() || !handle_initial_connection()) return false;

    if (!send_packet(MessageProtocol::build("REGISTER", username, -1, ""))) return false;
    if (!send_packet(MessageProtocol::build("PASSWORD", username, -1, password))) return false;

    std::string result_raw = get_one_message_from_socket();
    if (result_raw.empty()) return false;
    
    auto result_msg = MessageProtocol::parse(result_raw);
    if (result_msg.header == "REG_OK") {
        std::cout << "[SUCCESS] Регистрация прошла успешно: " << result_msg.message << std::endl;
        return true;
    } else {
        std::cerr << "[FAIL] Ошибка регистрации: " << result_msg.message << std::endl;
        return false;
    }
}

bool Client::run_interactive_session() {
    if (!connect_to_server() || !handle_initial_connection()) return false;
    
    std::cout << "\nПопытка аутентификации..." << std::endl;
    if (!handle_authentication()) {
        return false;
    }
    
    std::cout << "\nАутентификация успешна. Вход в интерактивный режим." << std::endl;

    while (true) {
        std::cout << "\nВведите команду (sign, getkey, exit): ";
        std::string choice;
        std::cin >> choice;

        if (choice == "sign") {
            handle_signing();
        } else if (choice == "getkey") {
            handle_get_public_key();
        } else if (choice == "exit") {
            std::cout << "[CLIENT] Отправка запроса на выход (LOGOUT)..." << std::endl;
            send_packet(MessageProtocol::build("LOGOUT", username, -1, ""));
            break;
        } else {
            std::cout << "Неизвестная команда." << std::endl;
        }
    }
    return true;
}

bool Client::handle_initial_connection() {
    auto response_msg = receive_formatted_packet();
    if (response_msg.header == "CONN_ACCEPT") {
        std::cout << "[CLIENT] Соединение установлено: " << response_msg.message << std::endl;
        return true;
    } else {
        std::cerr << "[CLIENT] Соединение отклонено: " << response_msg.message << std::endl;
        return false;
    }
}

bool Client::handle_authentication() {
    if (!send_packet(MessageProtocol::build("LOGIN", username, -1, ""))) return false;

    std::string challenge_raw = get_one_message_from_socket();
    if (challenge_raw.empty()) return false;
    
    auto challenge_msg = MessageProtocol::parse(challenge_raw);
    if (challenge_msg.header != "CHALLENGE") {
        std::cerr << "[ERROR] Ожидался CHALLENGE, но получен '" << challenge_msg.header << "'" << std::endl;
        return false;
    }
    std::string nonce = challenge_msg.message;
    
    std::string pass_hash = CryptoUtils::generate_hash(password);
    std::string response_data = CryptoUtils::generate_hash(pass_hash + nonce);
    if (!send_packet(MessageProtocol::build("RESPONSE", username, -1, response_data))) return false;

    std::string result_raw = get_one_message_from_socket();
    if (result_raw.empty()) return false;

    auto result_msg = MessageProtocol::parse(result_raw);
    if (result_msg.header == "AUTH_OK") {
        return true;
    } else {
        std::cerr << "[FAIL] Ошибка аутентификации: " << result_msg.message << std::endl;
        return false;
    }
}

void Client::handle_signing() {
    send_packet(MessageProtocol::build("SIGN_HASH", username, -1, ""));
    
    std::string test_hash = "5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8";
    send_packet(test_hash);

    auto sign_msg = receive_formatted_packet();
    if(sign_msg.header.empty()) return;

    if (sign_msg.header == "SIGN_SUCCESS") {
        std::cout << "[SUCCESS] Получена подпись: " << sign_msg.message << std::endl;
    } else {
        std::cerr << "[FAIL] Ошибка подписи: " << sign_msg.message << std::endl;
    }
}

void Client::handle_get_public_key() {
    send_packet(MessageProtocol::build("GET_PUB_KEY", username, -1, ""));

    auto key_n_msg = receive_formatted_packet();
    if (key_n_msg.header == "PUB_KEY_N") {
        std::cout << "[SUCCESS] Получен ключ N: " << key_n_msg.message << std::endl;
    } else {
         std::cerr << "[FAIL] Ошибка получения ключа N: " << key_n_msg.message << std::endl;
         return;
    }
    
    auto key_e_msg = receive_formatted_packet();
    if (key_e_msg.header == "PUB_KEY_E") {
        std::cout << "[SUCCESS] Получен ключ E: " << key_e_msg.message << std::endl;
    } else {
         std::cerr << "[FAIL] Ошибка получения ключа E: " << key_e_msg.message << std::endl;
    }
}

bool Client::connect_to_server() {
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) { perror("socket"); return false; }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) { perror("inet_pton"); return false; }

    if (connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) { perror("connect"); return false; }
    std::cout << "[CLIENT] Успешно подключен." << std::endl;
    return true;
}

void Client::disconnect() {
    if (socket_fd >= 0) { close(socket_fd); socket_fd = -1; std::cout << "[CLIENT] Соединение закрыто." << std::endl; }
}

bool Client::send_packet(const std::string& data) {
    if (socket_fd < 0) return false;
    ssize_t bytes_sent = send(socket_fd, data.c_str(), data.length(), MSG_NOSIGNAL);
    if (bytes_sent < 0) { perror("send"); return false; }
    return true;
}
// --- Конец: Класс Клиента ---


// --- Начало: Функция main ---
void print_usage() {
    std::cerr << "Usage: ./client <ip> <port> <username> <password> <command>\n"
              << "Commands:\n"
              << "  register   - Register a new user and exit.\n"
              << "  login      - Login and start an interactive session.\n";
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        print_usage();
        return 1;
    }
    std::string ip = argv[1];
    uint16_t port = std::stoi(argv[2]);
    std::string username = argv[3];
    std::string password = argv[4];
    std::string command = argv[5];

    try {
        Client client(ip, port, username, password);
        if (command == "register") {
            client.run_registration();
        } else if (command == "login") {
            client.run_interactive_session();
        } else {
            std::cerr << "Error: Unknown command '" << command << "'" << std::endl;
            print_usage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] An unexpected error occurred: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
// --- Конец: Функция main ---