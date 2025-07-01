#include "AppLogic.h"

// Прямые зависимости
#include "../Protocol_utils/protocol_utils.h"
#include "../Crypto_utils/crypto_utils.h"

// Системные инклюды
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>
#include <cerrno>
#include <cstring>

// --- Конструктор и Деструктор ---

AppLogic::AppLogic(
    const std::string& ip, uint16_t port, const std::string& username,
    const std::string& password, std::shared_ptr<logger> logger_instance,
    const std::string& log_path
) :
    m_server_ip(ip),
    m_server_port(port),
    m_user_name(username),
    m_user_password(password),
    m_logger(logger_instance),
    m_log_path(log_path)
{
    if (!m_logger) {
        throw std::invalid_argument("Logger instance in AppLogic cannot be null.");
    }
}

AppLogic::~AppLogic() {
    disconnect();
}

// --- ОСНОВНЫЕ СЦЕНАРИИ ---

void AppLogic::run_login_flow() {
    m_logger->write_log(m_log_path, "[AppLogic] Запуск клиента для '" + m_user_name + "' в режиме АУТЕНТИФИКАЦИИ.");
    if (!connect_to_server()) {
        m_console.show_error("Не удалось подключиться к серверу.");
        return;
    }
    if (perform_authentication()) {
        main_loop();
    } // Сообщение об ошибке аутентификации уже выводится внутри perform_authentication
    disconnect();
    m_console.show_message("Работа клиента завершена.");
    m_logger->write_log(m_log_path, "[AppLogic] Клиент штатно завершил работу.");
}

void AppLogic::run_registration_flow() {
    m_logger->write_log(m_log_path, "[AppLogic] Запуск клиента для '" + m_user_name + "' в режиме РЕГИСТРАЦИИ.");
    if (!connect_to_server()) {
        m_console.show_error("Не удалось подключиться к серверу.");
        return;
    }
    
    m_logger->write_log(m_log_path, "[AppLogic] Начало процесса регистрации.");
    if (!send_message({ "REGISTER", m_user_name, -1, "" })) {
        m_console.show_error("Потеряно соединение с сервером при отправке запроса на регистрацию.");
        disconnect(); return;
    }
    
    if (!send_message({ "PASSWORD", m_user_name, -1, m_user_password })) {
        m_console.show_error("Потеряно соединение с сервером при отправке пароля.");
        disconnect(); return;
    }
    
    auto response = receive_message();
    if (!response) {
        m_console.show_error("Сервер разорвал соединение, не прислав ответ о регистрации.");
    } else if (response->header == "REG_OK") {
        m_logger->write_log(m_log_path, "[AppLogic] Регистрация успешна.");
        m_console.show_message("Регистрация пользователя '" + m_user_name + "' прошла успешно!");
    } else {
        // Обработка конкретной ошибки от сервера
        std::string error_msg = "Регистрация не удалась: " + response->message + " (код: " + response->header + ")";
        m_console.show_error(error_msg);
        m_logger->write_log(m_log_path, "[AppLogic] " + error_msg);
    }
    disconnect();
}


// --- Приватные методы ---

bool AppLogic::is_connected() const { return m_socket != -1; }

void AppLogic::disconnect() {
    if (is_connected()) {
        m_logger->write_log(m_log_path, "[AppLogic] Закрытие сокета.");
        ::close(m_socket);
        m_socket = -1;
    }
}

// --- Переписанные сетевые методы с обработкой ошибок ---

bool AppLogic::connect_to_server() {
    // ... (код метода без изменений, он уже хорош)
    m_logger->write_log(m_log_path, "[AppLogic] Попытка подключения к " + m_server_ip + ":" + std::to_string(m_server_port));
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket < 0) {  return false; }
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(m_server_port);
    if (inet_pton(AF_INET, m_server_ip.c_str(), &server_addr.sin_addr) <= 0) { disconnect(); return false; }
    if (::connect(m_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) { disconnect(); return false; }
    auto welcome_msg = receive_message();
    if (!welcome_msg) { return false; }
    if (welcome_msg->header == "CONN_REJECT") { disconnect(); return false; }
    if (welcome_msg->header != "CONN_ACCEPT") { disconnect(); return false; }
    return true;
}

bool AppLogic::send_message(const MessageProtocol::ParsedMessage& msg) {
    // ... (код метода без изменений)
    if (!is_connected()) return false;
    if (ProtocolUtils::send_formatted_message(m_socket, msg.header, msg.clientID, msg.messageID, msg.message) != 0) { disconnect(); return false; }
    return true;
}

std::optional<MessageProtocol::ParsedMessage> AppLogic::receive_message() {
    // ... (код метода без изменений)
    if (!is_connected()) return std::nullopt;
    auto msg = ProtocolUtils::receive_and_parse_message(m_socket);
    if (!msg) { disconnect(); }
    return msg;
}


// --- Методы бизнес-логики с новой обработкой ошибок ---

bool AppLogic::perform_authentication() {
    m_logger->write_log(m_log_path, "[AppLogic] Начало аутентификации.");
    
    if (!send_message({ "LOGIN", m_user_name, -1, "" })) return false;

    auto challenge_msg = receive_message();
    if (!challenge_msg) {
        m_console.show_error("Сервер не прислал challenge для аутентификации.");
        return false;
    }
    // Обрабатываем конкретные ошибки сервера на этом этапе
    if (challenge_msg->header != "CHALLENGE") {
        std::string error_msg = "Ошибка аутентификации: " + challenge_msg->message + " (код: " + challenge_msg->header + ")";
        m_console.show_error(error_msg);
        m_logger->write_log(m_log_path, "[AppLogic] " + error_msg);
        return false;
    }
    
    const std::string& nonce = challenge_msg->message;
    std::string pass_hash = CryptoUtils::generate_hash(m_user_password);
    std::string response_hash = CryptoUtils::generate_hash(pass_hash + nonce);

    if (!send_message({ "CHALLENGE_RESPONSE", m_user_name, -1, response_hash })) return false;
    
    auto auth_result = receive_message();
    if (auth_result && auth_result->header == "AUTH_OK") {
        m_console.show_message("Аутентификация прошла успешно! " + auth_result->message);
        m_logger->write_log(m_log_path, "[AppLogic] Аутентификация успешна.");
        return true;
    } else {
        std::string error_msg = auth_result
            ? "Аутентификация провалена: " + auth_result->message + " (код: " + auth_result->header + ")"
            : "Аутентификация провалена: сервер не отвечает.";
        m_console.show_error(error_msg);
        m_logger->write_log(m_log_path, "[AppLogic] " + error_msg);
        return false;
    }
}

void AppLogic::main_loop() {
    while (is_connected()) {
        UserMenuChoice choice = m_console.get_user_menu_choice();
        
        if (choice == UserMenuChoice::EXIT) {
            send_message({ "LOGOUT", m_user_name, -1, "" });
            break; 
        }

        switch (choice) {
            case UserMenuChoice::REQUEST_SIGNATURE: handle_signing_request(); break;
            case UserMenuChoice::VERIFY_LOCALLY: handle_verification_request(); break;
            case UserMenuChoice::UNKNOWN:
            default: m_console.show_error("Неверный выбор."); break;
        }
    }
}

void AppLogic::handle_signing_request() {
    std::string file_path = m_console.ask_filepath("Введите полный путь к файлу для подписи: ");
    if (file_path.empty()) return;

    std::string hex_hash;
    try {
        hex_hash = m_signature_service.hash_file(file_path);
    } catch (const std::exception& e) {
        m_console.show_error(e.what());
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка хеширования: " + std::string(e.what()));
        return;
    }
    
    if (!send_message({ "SIGN_HASH", m_user_name, -1, "" })) { return; }
    if (!send_message({ "HASH_DATA", m_user_name, -1, hex_hash })) { return; }
    
    auto response = receive_message();
    if (!response) {
        m_console.show_error("Сервер разорвал соединение во время ожидания подписи.");
        return;
    }
    
    if (response->header == "SIGN_SUCCESS") {
        const std::string& signature_hex = response->message;
        m_console.display_signature(signature_hex);
        try {
            m_signature_service.save_signature(file_path, signature_hex);
            m_console.show_message("Подпись сохранена в файл: " + file_path + ".sig");
        } catch (const std::exception& e) {
            m_console.show_error(e.what());
        }
    } else {
        std::string error_msg = "Не удалось получить подпись: " + response->message + " (код: " + response->header + ")";
        m_console.show_error(error_msg);
        m_logger->write_log(m_log_path, "[AppLogic] " + error_msg);
    }
}

void AppLogic::handle_verification_request() {
    BigInt n, e;
    if (!request_public_key(n, e)) { return; }
    
    std::string original_path = m_console.ask_filepath("Введите путь к ОРИГИНАЛЬНОМУ файлу: ");
    if (original_path.empty()) return;

    std::string signature_path = m_console.ask_filepath("Введите путь к файлу ПОДПИСИ (*.sig): ");
    if (signature_path.empty()) return;
    
    try {
        bool is_valid = m_signature_service.verify_signature(original_path, signature_path, n, e);
        m_console.display_verification_result(is_valid);
        m_logger->write_log(
            m_log_path, 
            std::string("[AppLogic] Проверка подписи завершена. Результат: ") + (is_valid ? "УСПЕХ" : "ПРОВАЛ")
        );
    } catch (const std::exception& e) {
        m_console.show_error(e.what());
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка при верификации: " + std::string(e.what()));
    }
}

bool AppLogic::request_public_key(BigInt& out_n, BigInt& out_e) {
    if (!send_message({ "GET_PUB_KEY", m_user_name, -1, "" })) return false;

    auto n_response = receive_message();
    auto e_response = receive_message();

    if (!n_response || !e_response) {
        m_console.show_error("Сервер разорвал соединение во время передачи публичного ключа.");
        return false;
    }

    if (n_response->header != "PUB_KEY_N" || e_response->header != "PUB_KEY_E") {
        std::string error_msg = "Ошибка протокола при получении ключа. Получены заголовки: " 
                              + n_response->header + ", " + e_response->header;
        m_console.show_error(error_msg);
        m_logger->write_log(m_log_path, "[AppLogic] " + error_msg);
        return false;
    }
    
    try {
        out_n = BigInt::fromHexString(n_response->message);
        out_e = BigInt::fromHexString(e_response->message);
        m_console.show_message("Публичный ключ успешно получен.");
        return true;
    } catch (const std::exception& e) {
        m_console.show_error("Не удалось разобрать компоненты ключа, полученные от сервера.");
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка конвертации ключа из HEX: " + std::string(e.what()));
        return false;
    }
}