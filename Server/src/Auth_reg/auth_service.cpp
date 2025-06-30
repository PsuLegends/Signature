#include "auth_service.h"

#include <iostream>

// Подключаем утилиты и протокол
#include "../Crypto_utils/crypto_utils.h"
#include "../Protocol/protocol.h"
#include "../Protocol_utils/protocol_utils.h"
#include "../Error/error.h"

// --- Конструктор ---
AuthService::AuthService(base& db, logger& logger_instance, const std::string& log_path)
    : db_ref(db), logger_ref(logger_instance), log_location(log_path) 
{
    logger_ref.write_log(log_location, "[INFO] [AuthService] Сервис аутентификации и регистрации инициализирован.");
}


// --- Аутентификация ---
bool AuthService::authenticateClient(int socket, const std::string& client_id) {
    const std::string log_prefix = "[AuthService] [Authenticate] | ClientID: " + client_id + " | ";

    // 1. ВЫБИРАЕМ пользователя и ЗАГРУЖАЕМ его данные в объект db_ref
    if (!db_ref.selectUserByName(client_id)) {
        logger_ref.write_log(log_location, log_prefix + "Failure - User not found in database.");
        std::cerr << "[WARN] " << log_prefix << "Попытка входа для несуществующего пользователя." << std::endl;
        
        // БЫЛО:
        // std::string packet = MessageProtocol::build("AUTH_FAIL", client_id, -1, "User not found");
        // ProtocolUtils::send_packet(socket, packet);
        
        // СТАЛО:
        ProtocolUtils::send_formatted_message(socket, "AUTH_FAIL", client_id, -1, "User not found");
        return false;
    }

    // --- Логика Challenge-Response остается прежней ---

    // 2. Генерируем "Вызов" (nonce)
    std::string nonce = CryptoUtils::generate_random_hex_string(16);
    {
        std::lock_guard<std::mutex> lock(challenges_mutex);
        active_challenges[socket] = nonce;
    }

    // 3. Отправляем nonce клиенту
    logger_ref.write_log(log_location, log_prefix + "Sending challenge.");
    if (ProtocolUtils::send_formatted_message(socket, "CHALLENGE", "server", -1, nonce) != 0) {
        logger_ref.write_log(log_location, log_prefix + "Failure - Could not send challenge packet.");
        removeChallenge(socket);
        return false;
    }

    // 4. Получаем "Ответ" от клиента
    auto response_opt = ProtocolUtils::receive_and_parse_message(socket, 1024);
    if (!response_opt) {
        logger_ref.write_log(log_location, log_prefix + "Failure - Client disconnected before sending response.");
        removeChallenge(socket);
        return false;
    }
    std::string client_response = response_opt->message;
    
    // 5. Проверяем "Ответ"
    std::string password_hash_from_db = db_ref.getCurrentHashedPassword();
    if (password_hash_from_db.empty()) {
        logger_ref.write_log(log_location, log_prefix + "Critical Failure - User found, but no password hash available.");
        // Отправляем ошибку клиенту
        ProtocolUtils::send_formatted_message(socket, "AUTH_FAIL", client_id, -1, "Internal server error");
        removeChallenge(socket);
        return false;
    }
    
    std::string expected_response = CryptoUtils::generate_hash(password_hash_from_db + nonce);
    removeChallenge(socket);

    if (client_response == expected_response) {
        // Успех!
        logger_ref.write_log(log_location, log_prefix + "Success - Authentication successful.");
        std::cout << "[INFO] " << log_prefix << "Аутентификация прошла успешно." << std::endl;

        // БЫЛО:
        // std::string ok_packet = MessageProtocol::build("AUTH_OK", client_id, -1, "Authentication successful");
        // ProtocolUtils::send_packet(socket, ok_packet);

        // СТАЛО:
        ProtocolUtils::send_formatted_message(socket, "AUTH_OK", client_id, -1, "Authentication successful");
        return true;
    } else {
        // Неудача
        logger_ref.write_log(log_location, log_prefix + "Failure - Invalid response.");
        std::cerr << "[WARN] " << log_prefix << "Неверный ответ на 'вызов'." << std::endl;
        
        // БЫЛО:
        // std::string fail_packet = MessageProtocol::build("AUTH_FAIL", client_id, -1, "Invalid credentials");
        // ProtocolUtils::send_packet(socket, fail_packet);

        // СТАЛО:
        ProtocolUtils::send_formatted_message(socket, "AUTH_FAIL", client_id, -1, "Invalid credentials");
        return false;
    }
}


// --- Регистрация ---
bool AuthService::registerClient(int socket, const std::string& client_id, const std::string& client_ip) {
    const std::string log_prefix = "[AuthService] [Register] | ClientID: " + client_id + " | IP: " + client_ip + " | ";
    
    // 1. Проверяем, не занят ли ID
    if (db_ref.selectUserByName(client_id)) {
        logger_ref.write_log(log_location, log_prefix + "Failure - User ID already exists.");
        std::cerr << "[WARN] " << log_prefix << "Попытка регистрации с уже существующим ID." << std::endl;

        // БЫЛО:
        // std::string packet = MessageProtocol::build("REG_FAIL", client_id, -1, "User ID already taken");
        // ProtocolUtils::send_packet(socket, packet);

        // СТАЛО:
        ProtocolUtils::send_formatted_message(socket, "REG_FAIL", client_id, -1, "User ID already taken");
        return false;
    }

    // 2. Получаем пароль от клиента
    auto password_msg_opt = ProtocolUtils::receive_and_parse_message(socket, 1024);
    if (!password_msg_opt) {
        logger_ref.write_log(log_location, log_prefix + "Failure - Client disconnected before sending password.");
        return false;
    }
    if (password_msg_opt->header != "PASSWORD") {
         logger_ref.write_log(log_location, log_prefix + "Failure - Expected PASSWORD header, but got " + password_msg_opt->header);
         ProtocolUtils::send_formatted_message(socket, "REG_FAIL", client_id, -1, "Protocol error: expected PASSWORD");
         return false;
    }
    std::string password = password_msg_opt->message;

    // 3. Проверяем сложность пароля
    if (password.length() < 8) {
        // Здесь уже использовалась правильная функция
        ProtocolUtils::send_formatted_message(socket, "REG_FAIL", client_id, -1, "Password is too short (min 8 chars)");
        return false;
    }

    // 4. Хешируем пароль
    std::string hashed_password = CryptoUtils::generate_hash(password);

    // 5. Вставляем нового пользователя в БД
    if (db_ref.insertUser(client_id, hashed_password, client_ip)) {
        logger_ref.write_log(log_location, log_prefix + "Success - User registered successfully.");
        std::cout << "[INFO] " << log_prefix << "Пользователь успешно зарегистрирован." << std::endl;
        
        // БЫЛО:
        // std::string packet = MessageProtocol::build("REG_OK", client_id, -1, "Registration successful");
        // ProtocolUtils::send_packet(socket, packet);
        
        // СТАЛО:
        ProtocolUtils::send_formatted_message(socket, "REG_OK", client_id, -1, "Registration successful");
        return true;
    } else {
        logger_ref.write_log(log_location, log_prefix + "Failure - Database error during user insertion.");
        
        // БЫЛО:
        // std::string packet = MessageProtocol::build("REG_FAIL", client_id, -1, "Internal server error");
        // ProtocolUtils::send_packet(socket, packet);

        // СТАЛО:
        ProtocolUtils::send_formatted_message(socket, "REG_FAIL", client_id, -1, "Internal server error");
        return false;
    }
}


// --- Вспомогательная функция для удаления nonce ---
void AuthService::removeChallenge(int socket) {
    std::lock_guard<std::mutex> lock(challenges_mutex);
    active_challenges.erase(socket);
}