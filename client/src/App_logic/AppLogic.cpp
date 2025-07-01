// Файл: App_logic/AppLogic.cpp
#include "AppLogic.h"

// Прямая зависимость от утилит протокола и криптографии
#include "../Protocol_utils/protocol_utils.h"
#include "../Crypto_utils/crypto_utils.h"

// Системные инклюды для работы с сокетами
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>
#include <cerrno>  // для errno
#include <cstring> // для strerror

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
    } else {
        m_console.show_error("Аутентификация не удалась. Отключение.");
    }

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
        disconnect(); return;
    }
    
    if (!send_message({ "PASSWORD", m_user_name, -1, m_user_password })) {
        disconnect(); return;
    }
    
    auto reg_result = receive_message();
    if (reg_result && reg_result->header == "REG_OK") {
        m_logger->write_log(m_log_path, "[AppLogic] Регистрация успешна.");
        m_console.show_message("Регистрация пользователя '" + m_user_name + "' прошла успешно!");
    } else {
        std::string error_details = reg_result ? reg_result->message : "сервер не отвечает";
        m_logger->write_log(m_log_path, "[AppLogic] Регистрация провалена: " + error_details);
        m_console.show_error("Регистрация не удалась: " + error_details);
    }
    
    disconnect();
}


// --- Приватные методы ---

bool AppLogic::is_connected() const {
    return m_socket != -1;
}

bool AppLogic::connect_to_server() {
    m_logger->write_log(m_log_path, "[AppLogic] Попытка подключения к " + m_server_ip + ":" + std::to_string(m_server_port));
    
    m_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_socket < 0) { 
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка создания сокета: " + std::string(strerror(errno)));
        return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(m_server_port);
    if (inet_pton(AF_INET, m_server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка: неверный IP адрес " + m_server_ip);
        disconnect();
        return false;
    }
    
    if (::connect(m_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка подключения к серверу: " + std::string(strerror(errno)));
        disconnect();
        return false;
    }
    
    auto welcome_msg = receive_message();
    if (!welcome_msg) {
        m_logger->write_log(m_log_path, "[AppLogic] Сервер не прислал приветственное сообщение.");
        return false;
    }
    
    if (welcome_msg->header == "CONN_REJECT") {
         m_logger->write_log(m_log_path, "[AppLogic] Отказ в соединении: " + welcome_msg->message);
         disconnect();
         return false;
    }
    
    if (welcome_msg->header != "CONN_ACCEPT") {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка: получено некорректное приветствие: " + welcome_msg->header);
        disconnect();
        return false;
    }
    
    m_logger->write_log(m_log_path, "[AppLogic] Соединение с сервером успешно установлено.");
    return true;
}

void AppLogic::disconnect() {
    if (is_connected()) {
        m_logger->write_log(m_log_path, "[AppLogic] Закрытие сокета.");
        ::close(m_socket);
        m_socket = -1;
    }
}

bool AppLogic::send_message(const MessageProtocol::ParsedMessage& msg) {
    if (!is_connected()) {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка отправки: нет активного соединения.");
        return false;
    }
    if (ProtocolUtils::send_formatted_message(m_socket, msg.header, msg.clientID, msg.messageID, msg.message) != 0) {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка отправки сообщения, разрыв соединения.");
        disconnect();
        return false;
    }
    return true;
}

std::optional<MessageProtocol::ParsedMessage> AppLogic::receive_message() {
    if (!is_connected()) return std::nullopt;
    auto msg = ProtocolUtils::receive_and_parse_message(m_socket);
    if (!msg) {
        m_logger->write_log(m_log_path, "[AppLogic] Соединение было разорвано во время ожидания сообщения.");
        disconnect();
    }
    return msg;
}

bool AppLogic::perform_authentication() {
    m_logger->write_log(m_log_path, "[AppLogic] Начало аутентификации.");
    
    if (!send_message({ "LOGIN", m_user_name, -1, "" })) return false;

    auto challenge_msg = receive_message();
    if (!challenge_msg || challenge_msg->header != "CHALLENGE") {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка: не получен корректный challenge от сервера.");
        return false;
    }
    
    const std::string& nonce = challenge_msg->message;
    std::string pass_hash = CryptoUtils::generate_hash(m_user_password);
    std::string response_hash = CryptoUtils::generate_hash(pass_hash + nonce);

    if (!send_message({ "CHALLENGE_RESPONSE", m_user_name, -1, response_hash })) return false;
    
    auto auth_result = receive_message();
    if (auth_result && auth_result->header == "AUTH_OK") {
        m_logger->write_log(m_log_path, "[AppLogic] Аутентификация успешна.");
        m_console.show_message("Аутентификация прошла успешно!");
        return true;
    } else {
        std::string error_details = auth_result ? auth_result->message : "сервер не отвечает";
        m_logger->write_log(m_log_path, "[AppLogic] Аутентификация провалена: " + error_details);
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
            default:
                m_console.show_error("Неверный выбор. Пожалуйста, попробуйте снова.");
                break;
        }
    }
}

void AppLogic::handle_signing_request() {
    m_logger->write_log(m_log_path, "[AppLogic] Пользователь запросил подпись файла.");
    
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
    
    // ================== ИСПРАВЛЕНИЕ ==================
    // ШАГ А: Отправляем команду, ЧТО мы хотим сделать. Тело сообщения пустое.
    m_logger->write_log(m_log_path, "[AppLogic] Отправка команды SIGN_HASH на сервер.");
    if (!send_message({ "SIGN_HASH", m_user_name, -1, "" })) {
        m_console.show_error("Не удалось отправить команду на сервер.");
        return;
    }

    // ШАГ Б: Отправляем ДАННЫЕ для этой команды. Заголовок можно сделать любым
    // информативным, например HASH_DATA, или даже оставить пустым, т.к. сервер его не проверяет.
    m_logger->write_log(m_log_path, "[AppLogic] Отправка хеша на сервер: " + hex_hash);
    if (!send_message({ "HASH_DATA", m_user_name, -1, hex_hash })) {
        m_console.show_error("Не удалось отправить хеш на сервер.");
        return;
    }
    // =================================================

    // Теперь получаем ответ (подпись)
    auto response = receive_message();
    if (response && response->header == "SIGN_SUCCESS") {
        // ... остальной код обработки подписи без изменений ...
        const std::string& signature_hex = response->message;
        m_console.display_signature(signature_hex);
        try {
            m_signature_service.save_signature(file_path, signature_hex);
            m_console.show_message("Подпись сохранена в файл: " + file_path + ".sig");
        } catch (const std::exception& e) {
            m_console.show_error(e.what());
        }
    } else {
        std::string err = response ? response->message : "сервер разорвал соединение";
        m_console.show_error("Не удалось получить подпись: " + err);
    }
}

void AppLogic::handle_verification_request() {
    m_logger->write_log(m_log_path, "[AppLogic] Пользователь запросил проверку подписи.");
    
    BigInt n, e;
    if (!request_public_key(n, e)) {
        m_console.show_error("Не удалось получить публичный ключ от сервера.");
        return;
    }
    m_console.show_message("Публичный ключ успешно получен.");
    
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
    m_logger->write_log(m_log_path, "[AppLogic] Запрос публичного ключа у сервера.");
    
    if (!send_message({ "GET_PUB_KEY", m_user_name, -1, "" })) return false;

    auto n_response = receive_message();
    if (!n_response || n_response->header != "PUB_KEY_N") {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка: не получена компонента N ключа.");
        return false;
    }
    auto e_response = receive_message();
    if (!e_response || e_response->header != "PUB_KEY_E") {
         m_logger->write_log(m_log_path, "[AppLogic] Ошибка: не получена компонента E ключа.");
        return false;
    }
    
    try {
        out_n = BigInt::fromHexString(n_response->message);
        out_e = BigInt::fromHexString(e_response->message);
        m_logger->write_log(m_log_path, "[AppLogic] Публичный ключ успешно получен и распарсен.");
        return true;
    } catch (const std::exception& e) {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка конвертации ключа из HEX: " + std::string(e.what()));
        return false;
    }
}