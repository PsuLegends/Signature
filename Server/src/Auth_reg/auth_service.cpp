#include "auth_service.h"
#include <iostream>
#include "../Crypto_utils/crypto_utils.h"
#include "../Protocol/protocol.h"
#include "../Protocol_utils/protocol_utils.h"
#include "../Error/error.h"
AuthService::AuthService(base& db, logger& logger_instance, const std::string& log_path)
    : db_ref(db), logger_ref(logger_instance), log_location(log_path) 
{
    logger_ref.write_log(log_location, "[INFO] [AuthService] Сервис аутентификации и регистрации инициализирован.");
}
bool AuthService::authenticateClient(int socket, const std::string& client_id) {
    const std::string log_prefix = "[AuthService] [Authenticate] | ClientID: " + client_id + " | ";
    if (!db_ref.selectUserByName(client_id)) {
        logger_ref.write_log(log_location, log_prefix + "Failure - User not found in database.");
        std::cerr << "[WARN] " << log_prefix << "Попытка входа для несуществующего пользователя." << std::endl;
        ProtocolUtils::send_formatted_message(socket, "AUTH_FAIL", client_id, -1, "User not found");
        return false;
    }
    std::string nonce = CryptoUtils::generate_random_hex_string(16);
    {
        std::lock_guard<std::mutex> lock(challenges_mutex);
        active_challenges[socket] = nonce;
    }
    logger_ref.write_log(log_location, log_prefix + "Sending challenge.");
    if (ProtocolUtils::send_formatted_message(socket, "CHALLENGE", "server", -1, nonce) != 0) {
        logger_ref.write_log(log_location, log_prefix + "Failure - Could not send challenge packet.");
        removeChallenge(socket);
        return false;
    }
    auto response_opt = ProtocolUtils::receive_and_parse_message(socket);
    if (!response_opt) {
        logger_ref.write_log(log_location, log_prefix + "Failure - Client disconnected before sending response.");
        removeChallenge(socket);
        return false;
    }
    std::string client_response = response_opt->message;

    std::string password_hash_from_db = db_ref.getCurrentHashedPassword();
    if (password_hash_from_db.empty()) {
        logger_ref.write_log(log_location, log_prefix + "Critical Failure - User found, but no password hash available.");
        ProtocolUtils::send_formatted_message(socket, "AUTH_FAIL", client_id, -1, "Internal server error");
        removeChallenge(socket);
        return false;
    }
    
    std::string expected_response = CryptoUtils::generate_hash(password_hash_from_db + nonce);
    removeChallenge(socket);

    if (client_response == expected_response) {
        logger_ref.write_log(log_location, log_prefix + "Success - Authentication successful.");
        std::cout << "[INFO] " << log_prefix << "Аутентификация прошла успешно." << std::endl;
        ProtocolUtils::send_formatted_message(socket, "AUTH_OK", client_id, -1, "Authentication successful");
        return true;
    } else {
        logger_ref.write_log(log_location, log_prefix + "Failure - Invalid response.");
        std::cerr << "[WARN] " << log_prefix << "Неверный ответ на 'вызов'." << std::endl;
        ProtocolUtils::send_formatted_message(socket, "AUTH_FAIL", client_id, -1, "Invalid credentials");
        return false;
    }
}
bool AuthService::registerClient(int socket, const std::string& client_id, const std::string& client_ip) {
    const std::string log_prefix = "[AuthService] [Register] | ClientID: " + client_id + " | IP: " + client_ip + " | ";
    if (db_ref.selectUserByName(client_id)) {
        logger_ref.write_log(log_location, log_prefix + "Failure - User ID already exists.");
        std::cerr << "[WARN] " << log_prefix << "Попытка регистрации с уже существующим ID." << std::endl;
        ProtocolUtils::send_formatted_message(socket, "REG_FAIL", client_id, -1, "User ID already taken");
        return false;
    }
    auto password_msg_opt = ProtocolUtils::receive_and_parse_message(socket);
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
    if (password.length() < 8) {
        ProtocolUtils::send_formatted_message(socket, "REG_FAIL", client_id, -1, "Password is too short (min 8 chars)");
        return false;
    }
    std::string hashed_password = CryptoUtils::generate_hash(password);
    if (db_ref.insertUser(client_id, hashed_password, client_ip)) {
        logger_ref.write_log(log_location, log_prefix + "Success - User registered successfully.");
        std::cout << "[INFO] " << log_prefix << "Пользователь успешно зарегистрирован." << std::endl;
        ProtocolUtils::send_formatted_message(socket, "REG_OK", client_id, -1, "Registration successful");
        return true;
    } else {
        logger_ref.write_log(log_location, log_prefix + "Failure - Database error during user insertion.");
        ProtocolUtils::send_formatted_message(socket, "REG_FAIL", client_id, -1, "Internal server error");
        return false;
    }
}
void AuthService::removeChallenge(int socket) {
    std::lock_guard<std::mutex> lock(challenges_mutex);
    active_challenges.erase(socket);
}
