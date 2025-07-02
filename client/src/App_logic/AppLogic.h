#pragma once
#include <string>
#include <memory>
#include <optional>
#include <cstdint>
#include "../Service/SignatureService.h"
#include "../UI/InteractiveConsole.h"
#include "../Logger/logger.h"
#include "../Rsa/rsa_crypto.h"
#include "../Protocol/protocol.h" 
class AppLogic {
public:
    AppLogic(
        const std::string& ip,
        uint16_t port,
        const std::string& username,
        const std::string& password,
        std::shared_ptr<logger> logger_instance,
        const std::string& log_path
    );
    ~AppLogic();
    AppLogic(const AppLogic&) = delete;
    AppLogic& operator=(const AppLogic&) = delete;
    void run_login_flow();
    void run_registration_flow();

private:
    bool connect_to_server();
    void disconnect();
    bool send_message(const MessageProtocol::ParsedMessage& msg);
    std::optional<MessageProtocol::ParsedMessage> receive_message();
    bool is_connected() const;
    bool perform_authentication();
    void main_loop();
    void handle_signing_request();
    void handle_verification_request();
    bool request_public_key(BigInt& out_n, BigInt& out_e);
    int m_socket = -1; 
    std::string m_server_ip;
    uint16_t m_server_port;
    std::string m_user_name;
    std::string m_user_password;
    std::string m_log_path;
    SignatureService m_signature_service;
    InteractiveConsole m_console;
    std::shared_ptr<logger> m_logger;
};