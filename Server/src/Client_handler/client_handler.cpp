#include "client_handler.h"
#include <iostream>
#include <unistd.h> // для close()
#include <arpa/inet.h> // для inet_ntop
#include <thread> // для sleep_for

// Включаем утилиты и протокол
#include "../Protocol_utils/protocol_utils.h"
#include "../Protocol/protocol.h"
#include "../Error/error.h"

// --- Реализация менеджера RAII ---
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
      connection_manager(client_counter) // Счетчик увеличивается здесь
{
    char ip_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), ip_buf, INET_ADDRSTRLEN);
    this->client_ip_str = ip_buf;
}

void ClientHandler::run() {
    try {
        // Логируем, что для нового клиента был запущен выделенный поток
        logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Новый поток запущен для клиента " + client_ip_str);

        // --- ШАГ 0: ПРИВЕТСТВИЕ КЛИЕНТА (ИСПРАВЛЕНИЕ DEADLOCK'А) ---
        // Первым делом мы отправляем клиенту подтверждение, что соединение принято.
        // Теперь клиент знает, что можно начинать общение.
        if (ProtocolUtils::send_formatted_message(socket_fd, "CONN_ACCEPT", "server", -1, "Соединение успешно установлено.") != 0) {
            // Если мы не можем даже отправить приветствие, продолжать нет смысла.
            logger_ptr->write_log(log_location, "[WARN] [ClientHandler] Не удалось отправить приветствие клиенту " + client_ip_str + ". Закрытие соединения.");
            close(socket_fd);
            return;
        }

        // --- ШАГ 1: ПОЛУЧЕНИЕ НАЧАЛЬНОЙ ОПЕРАЦИИ ОТ КЛИЕНТА ---
        // Теперь, когда клиент получил наше приветствие, он отправит свой запрос.
        auto initial_msg_opt = ProtocolUtils::receive_and_parse_message(socket_fd);
        if (!initial_msg_opt) {
            // Если клиент отключается сразу после приветствия, это нормально. Просто логируем и выходим.
            logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_ip_str + " отсоединился до начала операции.");
            close(socket_fd);
            return;
        }

        // Распарсим полученное сообщение
        MessageProtocol::ParsedMessage initial_msg = *initial_msg_opt;
        this->client_id_str = initial_msg.clientID; // Сохраняем ID клиента для дальнейшего использования
        const std::string operation_type = initial_msg.header; // Тип операции (LOGIN или REGISTER)

        logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_id_str + " (" + client_ip_str + ") запрашивает операцию: " + operation_type);
        
        // --- ШАГ 2: ОБРАБОТКА РЕГИСТРАЦИИ ИЛИ АУТЕНТИФИКАЦИИ ---
        bool authenticated = false;
        if (operation_type == "REGISTER") {
            // Передаем управление сервису регистрации.
            // Соединение, как правило, закрывается после регистрации.
            auth_service->registerClient(socket_fd, client_id_str, client_ip_str);
        
        } else if (operation_type == "LOGIN") {
            // Передаем управление сервису аутентификации.
            if (auth_service->authenticateClient(socket_fd, client_id_str)) {
                authenticated = true; // Если аутентификация успешна, устанавливаем флаг
            }

        } else {
            logger_ptr->write_log(log_location, "[WARN] [ClientHandler] Неизвестная начальная операция: " + operation_type + " от клиента " + client_id_str);
            ProtocolUtils::send_formatted_message(socket_fd, "OP_UNKNOWN", client_id_str, -1, "Неизвестная начальная операция.");
        }

        // --- ШАГ 3: ОСНОВНОЙ ЦИКЛ ОБРАБОТКИ ЗАПРОСОВ (ЕСЛИ АУТЕНТИФИЦИРОВАН) ---
        if (authenticated) {
            logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_id_str + " аутентифицирован. Переход в режим обработки запросов.");
            processRequests();
        }

    } catch (const std::exception& e) {
        // Отлов любых непредвиденных исключений в потоке для предотвращения падения сервера
        logger_ptr->write_log(log_location, "[ERROR] [ClientHandler] Критическое исключение в потоке клиента " + client_id_str + " (" + client_ip_str + "): " + e.what());
    }

    // --- ШАГ 4: ЗАВЕРШЕНИЕ РАБОТЫ И ОЧИСТКА ---
    // Эта точка достигается либо после штатного завершения (выход, регистрация), либо из-за ошибки.
    // Сокет будет закрыт в любом случае.
    logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Закрытие соединения и завершение потока для клиента " + client_id_str + " (" + client_ip_str + ").");
    close(socket_fd);
    
    // Деструктор ClientConnectionManager будет вызван автоматически при выходе из функции,
    // и счетчик активных клиентов уменьшится (принцип RAII).
}


void ClientHandler::processRequests() {
    while (true) {
        /*std::string packet_raw = ProtocolUtils::receive_packet(socket_fd, 1024);
        if (packet_raw.empty()) {
            logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_id_str + " отсоединился.");
            break;
        }*/

        auto request_opt = ProtocolUtils::receive_and_parse_message(socket_fd);
        if (!request_opt) {
            logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_id_str + " отсоединился.");
            break;
        }
        MessageProtocol::ParsedMessage request = *request_opt;
        const std::string& sig_op = request.header;

        if (sig_op == "SIGN_HASH") { // Замена для "11"
            handleSignOperation();
        } else if (sig_op == "GET_PUB_KEY") { // Замена для "22"
            handleGetPublicKeyOperation();
        } else if (sig_op == "LOGOUT") { // Замена для "0"
            logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_id_str + " запросил отключение.");
            break;
        } else {
            logger_ptr->write_log(log_location, "[WARN] [ClientHandler] Неизвестная операция подписи '" + sig_op + "' от " + client_id_str);
            ProtocolUtils::send_formatted_message(socket_fd, "OP_UNKNOWN", client_id_str, -1, "Неизвестная операция.");
        }
    }
}

void ClientHandler::handleSignOperation() {
    logger_ptr->write_log(log_location, "[INFO] [ClientHandler] " + client_id_str + " запрашивает подпись хеша.");
    auto hash_msg_opt = ProtocolUtils::receive_and_parse_message(socket_fd);
    if (!hash_msg_opt) {
        logger_ptr->write_log(log_location, "[WARN] [ClientHandler] " + client_id_str + " отсоединился перед отправкой хеша.");
        return;
    }
    // Предполагаем, что хеш находится в поле 'message'
    std::string hash_to_sign = hash_msg_opt->message;
    if(hash_to_sign.empty()){
        return;
    }
    
    try {
        std::string signature = signing_service->signHash(hash_to_sign);
        ProtocolUtils::send_formatted_message(socket_fd, "SIGN_SUCCESS", client_id_str, -1, signature);
    } catch (const SigningServiceError& e) {
        logger_ptr->write_log(log_location, "[ERROR] [ClientHandler] Ошибка подписи для " + client_id_str + ": " + e.what());
        ProtocolUtils::send_formatted_message(socket_fd, "SIGN_FAIL", client_id_str, -1, e.what());
    }
}

void ClientHandler::handleGetPublicKeyOperation() {
    logger_ptr->write_log(log_location, "[INFO] [ClientHandler] " + client_id_str + " запрашивает публичный ключ.");
    try {
        std::string n_hex = signing_service->getPublicKeyN_Hex();
        std::string e_hex = signing_service->getPublicKeyE_Hex();

        // Отправляем части ключа в раздельных сообщениях
        ProtocolUtils::send_formatted_message(socket_fd, "PUB_KEY_N", client_id_str, -1, n_hex);
        std::this_thread::sleep_for(std::chrono::milliseconds(20)); // Пауза для надежности
        ProtocolUtils::send_formatted_message(socket_fd, "PUB_KEY_E", client_id_str, -1, e_hex);
        
    } catch (const SigningServiceError& e) {
        logger_ptr->write_log(log_location, "[ERROR] [ClientHandler] Ошибка получения публичного ключа для " + client_id_str + ": " + e.what());
        ProtocolUtils::send_formatted_message(socket_fd, "KEY_FAIL", client_id_str, -1, e.what());
    }
}
