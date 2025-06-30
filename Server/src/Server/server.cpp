#include "server.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include "../Client_handler/client_handler.h" // Важно

Server::Server(uint16_t port, const std::string& log_path)
    : port(port), log_location(log_path)
{
    try {
        // Инициализация сервисов (Внедрение зависимостей)
        logger_ptr = std::make_shared<logger>();
        logger_ptr->write_log(log_location, "[INFO] [Server] Инициализация сервера...");
        
        db_ptr = std::make_shared<base>(); // Конструктор 'base' уже выполняет подключение
        
        auth_service_ptr = std::make_shared<AuthService>(*db_ptr, *logger_ptr, log_location);
        
        // Пути к ключам должны приходить из конфига, пока задаем их здесь
        signing_service_ptr = std::make_shared<SigningService>("private.key", "public_n.key", "public_e.key");

        logger_ptr->write_log(log_location, "[INFO] [Server] Все сервисы успешно инициализированы.");
    } catch (const std::exception& e) {
        if(logger_ptr) {
            logger_ptr->write_log(log_location, std::string("[CRITICAL] [Server] Ошибка инициализации: ") + e.what());
        }
        std::cerr << "[CRITICAL] [Server] Ошибка инициализации: " << e.what() << std::endl;
        throw; // Перебрасываем исключение, чтобы завершить программу
    }
}

void Server::run() {
    setup();
    acceptLoop();
}

void Server::setup() {
    logger_ptr->write_log(log_location, "[INFO] [Server] Настройка сокета...");
    server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd < 0) {
        throw critical_error("Ошибка при создании сокета сервера.");
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket_fd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        throw critical_error("Ошибка bind() для порта " + std::to_string(port));
    }

    if (listen(server_socket_fd, 10) != 0) {
        throw critical_error("Ошибка listen()");
    }
    
    logger_ptr->write_log(log_location, "[INFO] [Server] Сервер слушает порт " + std::to_string(port));
    std::cout << "[INFO] [Server] Сервер слушает порт " << std::to_string(port) << std::endl;
}

void Server::acceptLoop() {
    logger_ptr->write_log(log_location, "[INFO] [Server] Вход в цикл принятия соединений...");
    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket_fd, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket < 0) {
            logger_ptr->write_log(log_location, "[ERROR] [Server] accept() завершился с ошибкой.");
            continue; 
        }

        // Проверка лимита клиентов
        if (active_clients >= MAX_CLIENTS) {
            logger_ptr->write_log(log_location, "[WARN] [Server] Достигнут лимит клиентов. Новое соединение отклонено.");
            // Отправим отказ и закроем. Это единственное сообщение, которое здесь уместно.
            ProtocolUtils::send_formatted_message(client_socket, "CONN_REJECT", "server", -1, "Сервер занят. Попробуйте позже.");
            close(client_socket);
            continue;
        }

        // Логику успешного соединения переносим в ClientHandler
        // Больше не отправляем "CONN_ACCEPT" и не логируем здесь
        
        // Создаем и запускаем ClientHandler в новом потоке
        auto handler = std::make_shared<ClientHandler>(client_socket, client_addr, 
                                                       auth_service_ptr, signing_service_ptr, 
                                                       logger_ptr, log_location, active_clients);

        std::thread client_thread([handler]() {
            handler->run();
        });
        
        client_thread.detach(); 
    }
}