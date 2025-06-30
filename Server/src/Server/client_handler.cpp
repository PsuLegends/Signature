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
        logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Новый поток запущен для клиента " + client_ip_str);
        
        // 1. Получить начальную операцию (логин или регистрация)
        std::string initial_packet = ProtocolUtils::receive_packet(socket_fd, 1024);
        if (initial_packet.empty()) {
            logger_ptr->write_log(log_location, "[WARN] [ClientHandler] Клиент " + client_ip_str + " отсоединился до начала операции.");
            close(socket_fd);
            return;
        }

        MessageProtocol::ParsedMessage initial_msg = MessageProtocol::parse(initial_packet);
        this->client_id_str = initial_msg.clientID;
        const std::string operation_type = initial_msg.header; // Предполагаем, что заголовок - это тип операции

        logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_id_str + " запрашивает операцию: " + operation_type);
        
        // 2. Обработать регистрацию или аутентификацию
        bool authenticated = false;
        if (operation_type == "REGISTER") { // Используем более описательный заголовок
            // Сервис регистрации получит пароль и обработает запрос
            auth_service->registerClient(socket_fd, client_id_str, client_ip_str);
            // Соединение закрывается после регистрации, как в вашей оригинальной логике
        } else if (operation_type == "LOGIN") { // Заголовок для входа
            // Сервис аутентификации выполняет весь процесс "Вызов-ответ"
            if (auth_service->authenticateClient(socket_fd, client_id_str)) {
                authenticated = true;
            }
        } else {
            logger_ptr->write_log(log_location, "[WARN] [ClientHandler] Неизвестная начальная операция: " + operation_type);
        }

        // 3. Если аутентифицирован, войти в цикл обработки запросов
        if (authenticated) {
            logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_id_str + " аутентифицирован. Обработка запросов...");
            processRequests();
        }

    } catch (const std::exception& e) {
        logger_ptr->write_log(log_location, "[ERROR] [ClientHandler] Исключение в потоке клиента " + client_ip_str + ": " + e.what());
    }

    // 4. Закрыть сокет в конце жизненного цикла клиента
    logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Закрытие соединения для клиента " + client_ip_str);
    close(socket_fd);
    // Счетчик клиентов будет автоматически уменьшен, когда объект уничтожится (благодаря RAII)
}

void ClientHandler::processRequests() {
    while (true) {
        std::string packet_raw = ProtocolUtils::receive_packet(socket_fd, 1024);
        if (packet_raw.empty()) {
            logger_ptr->write_log(log_location, "[INFO] [ClientHandler] Клиент " + client_id_str + " отсоединился.");
            break;
        }

        MessageProtocol::ParsedMessage request = MessageProtocol::parse(packet_raw);
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
    std::string hash_to_sign = ProtocolUtils::receive_packet(socket_fd, 1024); // Предполагаем, что хеш приходит в отдельном пакете
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
