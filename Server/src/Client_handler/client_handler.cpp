// Файл: Client_handler/client_handler.cpp
#include "client_handler.h"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <sstream>

// Включаем утилиты и протокол
#include "../Protocol_utils/protocol_utils.h"
#include "../Protocol/protocol.h"
#include "../Error/error.h"

// --- Реализация ClientConnectionManager ---
ClientConnectionManager::ClientConnectionManager(std::atomic<int>& counter)
    : client_counter(counter) {
    client_counter.fetch_add(1);
}

ClientConnectionManager::~ClientConnectionManager() {
    client_counter.fetch_sub(1);
}


// --- Реализация ClientHandler ---
ClientHandler::ClientHandler(int socket, sockaddr_in addr,
                             std::shared_ptr<AuthService> auth,
                             std::shared_ptr<SigningService> signing,
                             std::shared_ptr<logger> logger_instance,
                             const std::string& log_path,
                             std::atomic<int>& client_counter)
    : socket_fd(socket), auth_service(auth), signing_service(signing), 
      logger_ptr(logger_instance), log_location(log_path), 
      connection_manager(client_counter)
{
    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ip_buf, INET_ADDRSTRLEN);
    this->client_ip_str = ip_buf;
}

void ClientHandler::sendErrorAndLog(const std::string& errorHeader, const std::string& clientMessage, const std::string& logMessage) {
    const std::string log_prefix = "[ClientHandler] | ClientID: " + client_id_str + " | IP: " + client_ip_str + " | ";
    logger_ptr->write_log(log_location, log_prefix + "ОШИБКА: " + logMessage);
    ProtocolUtils::send_formatted_message(socket_fd, errorHeader, "server", -1, clientMessage);
}


void ClientHandler::run() {
    std::string client_info_str = "[Клиент " + client_ip_str + "]";
    
    try {
        logger_ptr->write_log(log_location, "[INFO] " + client_info_str + " Подключен. Запуск потока-обработчика.");
        std::cout << "[INFO] " << client_info_str << " Подключен." << std::endl;

        if (ProtocolUtils::send_formatted_message(socket_fd, "CONN_ACCEPT", "server", -1, "Соединение успешно установлено.") != 0) {
            logger_ptr->write_log(log_location, "[WARN] " + client_info_str + " Не удалось отправить приветствие. Закрытие соединения.");
            std::cerr << "[WARN] " << client_info_str << " Не удалось отправить приветствие." << std::endl;
            close(socket_fd);
            return;
        }

        auto initial_msg_opt = ProtocolUtils::receive_and_parse_message(socket_fd);
        if (!initial_msg_opt) {
            logger_ptr->write_log(log_location, "[INFO] " + client_info_str + " Отсоединился до начала операции.");
            std::cout << "[INFO] " << client_info_str << " Немедленно отсоединился." << std::endl;
            close(socket_fd);
            return;
        }

        this->client_id_str = initial_msg_opt->clientID; 
        client_info_str = "[Клиент " + client_id_str + " (" + client_ip_str + ")]";

        const std::string operation_type = initial_msg_opt->header;
        logger_ptr->write_log(log_location, "[INFO] " + client_info_str + " Запросил операцию: " + operation_type);
        std::cout << "[INFO] " << client_info_str << " Запрос на операцию: '" << operation_type << "'." << std::endl;

        bool authenticated = false;
        if (operation_type == "REGISTER") {
            auth_service->registerClient(socket_fd, client_id_str, client_ip_str);
        } else if (operation_type == "LOGIN") {
            if (auth_service->authenticateClient(socket_fd, client_id_str)) {
                authenticated = true;
            }
        } else {
            sendErrorAndLog("OP_UNKNOWN", "Неизвестная начальная операция.", "Получена неизвестная операция: '" + operation_type + "'");
        }

        if (authenticated) {
            logger_ptr->write_log(log_location, "[INFO] " + client_info_str + " Аутентифицирован. Переход в режим обработки запросов.");
            std::cout << "[OK]   " << client_info_str << " Успешная аутентификация." << std::endl;
            processRequests();
        } else if (operation_type == "LOGIN") {
             std::cout << "[WARN] " << client_info_str << " Не прошел аутентификацию." << std::endl;
        }

    } catch (const std::exception& e) {
        logger_ptr->write_log(log_location, "[ERROR] " + client_info_str + " Критическое исключение в потоке: " + e.what());
        std::cerr << "[ERROR] " << client_info_str << " Критическая ошибка: " << e.what() << std::endl;
    }

    logger_ptr->write_log(log_location, "[INFO] " + client_info_str + " Завершение потока, закрытие соединения.");
    std::cout << "[INFO] " << client_info_str << " Отключен." << std::endl;
    close(socket_fd);
}


void ClientHandler::processRequests() {
    const std::string client_info_str = "[Клиент " + client_id_str + "]";

    while (true) {
        auto request_opt = ProtocolUtils::receive_and_parse_message(socket_fd);
        if (!request_opt) {
            break; // Клиент отсоединился
        }
        
        const std::string& request_header = request_opt->header;
        std::cout << "[RECV] " << client_info_str << " Получен запрос: '" << request_header << "'" << std::endl;

        if (request_header == "SIGN_HASH") {
            handleSignOperation();
        } else if (request_header == "GET_PUB_KEY") {
            handleGetPublicKeyOperation();
        } else if (request_header == "LOGOUT") {
            break; 
        } else {
            sendErrorAndLog("OP_UNKNOWN", "Неизвестный тип операции: " + request_header, "Получена неизвестная команда: '" + request_header + "'");
            std::cerr << "[WARN] " << client_info_str << " Прислал неизвестную команду: " << request_header << std::endl;
        }
    }
}


void ClientHandler::handleSignOperation() {
    const std::string client_info_str = "[Клиент " + client_id_str + "]";
    std::cout << "[INFO] " << client_info_str << " Ожидает хеш для подписи..." << std::endl;

    auto hash_msg_opt = ProtocolUtils::receive_and_parse_message(socket_fd);
    if (!hash_msg_opt) { return; }
    
    std::string hash_to_sign = hash_msg_opt->message;
    std::cout << "[INFO] " << client_info_str << " Получен хеш. Передача в сервис подписи." << std::endl;

    if (hash_to_sign.empty()) {
        sendErrorAndLog("PROTO_ERROR", "Хеш для подписи не может быть пустым.", "Прислан пустой хеш для подписи.");
        std::cerr << "[WARN] " << client_info_str << " Прислал пустой хеш." << std::endl;
        return;
    }
    
    try {
        std::string signature = signing_service->signHash(hash_to_sign);
        ProtocolUtils::send_formatted_message(socket_fd, "SIGN_SUCCESS", client_id_str, -1, signature);
        std::cout << "[SEND] " << client_info_str << " Подпись успешно сгенерирована и отправлена." << std::endl;

    } catch (const SigningServiceError& e) {
        sendErrorAndLog("SIGN_FAIL", "Внутренняя ошибка сервера при создании подписи.", "Ошибка сервиса подписи: " + std::string(e.what()));
        std::cerr << "[ERROR] " << client_info_str << " Ошибка при генерации подписи." << std::endl;
    }
}

void ClientHandler::handleGetPublicKeyOperation() {
    const std::string client_info_str = "[Клиент " + client_id_str + "]";
    
    try {
        std::string n_hex = signing_service->getPublicKeyN_Hex();
        std::string e_hex = signing_service->getPublicKeyE_Hex();

        ProtocolUtils::send_formatted_message(socket_fd, "PUB_KEY_N", client_id_str, -1, n_hex);
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        ProtocolUtils::send_formatted_message(socket_fd, "PUB_KEY_E", client_id_str, -1, e_hex);
        std::cout << "[SEND] " << client_info_str << " Публичный ключ отправлен." << std::endl;

    } catch (const SigningServiceError& e) {
        sendErrorAndLog("KEY_FAIL", "Внутренняя ошибка сервера при получении ключа.", "Ошибка сервиса ключей: " + std::string(e.what()));
        std::cerr << "[ERROR] " << client_info_str << " Ошибка при получении публичного ключа." << std::endl;
    }
}