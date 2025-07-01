
#include "server.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <algorithm> 
#include <csignal>   
#include "../Client_handler/client_handler.h"
#include "../Protocol_utils/protocol_utils.h"
Server* g_server_instance = nullptr;

void signal_handler(int signum) {
    if (g_server_instance) {
        std::cout << "\n[INFO] [Server] Получен сигнал " << signum << ". Начинаю остановку..." << std::endl;
    }
    exit(signum);
}
Server::Server(uint16_t port, const std::string& log_path)
    : port(port), log_location(log_path)
{
    g_server_instance = this; 

    try {
        logger_ptr = std::make_shared<logger>();
        logger_ptr->write_log(log_location, "[INFO] [Server] Инициализация сервера...");
        
        db_ptr = std::make_shared<base>();
        
        auth_service_ptr = std::make_shared<AuthService>(*db_ptr, *logger_ptr, log_location);
        
        signing_service_ptr = std::make_shared<SigningService>("private.key", "public_n.key", "public_e.key");

        logger_ptr->write_log(log_location, "[INFO] [Server] Все сервисы успешно инициализированы.");
    } catch (const std::exception& e) {
        if (logger_ptr) {
            logger_ptr->write_log(log_location, std::string("[CRITICAL] [Server] Ошибка инициализации: ") + e.what());
        }
        std::cerr << "[CRITICAL] [Server] Ошибка инициализации: " << e.what() << std::endl;
        throw;
    }
}

Server::~Server() {
    m_is_running = false; 
    
 
    std::cout << "\n[INFO] [Server] Ожидание завершения клиентских потоков..." << std::endl;
    std::lock_guard<std::mutex> lock(m_threads_mutex);
    for (std::thread& t : m_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    std::cout << "[INFO] [Server] Все потоки завершены. Сервер остановлен." << std::endl;
    g_server_instance = nullptr;
}

void Server::run() {
    
    signal(SIGINT, signal_handler);  
    signal(SIGTERM, signal_handler); 

    setup();
    acceptLoop();
}

void Server::setup() {
    logger_ptr->write_log(log_location, "[INFO] [Server] Настройка сокета...");
    server_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_fd < 0) {
        throw critical_error("Ошибка при создании сокета сервера.");
    }

    int opt = 1;
    if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        throw critical_error("Ошибка setsockopt(SO_REUSEADDR).");
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket_fd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        throw critical_error("Ошибка bind() для порта " + std::to_string(port));
    }

    if (listen(server_socket_fd, SOMAXCONN) != 0) { 
        throw critical_error("Ошибка listen()");
    }
    
    logger_ptr->write_log(log_location, "[INFO] [Server] Сервер слушает порт " + std::to_string(port));
    std::cout << "[INFO] [Server] Сервер запущен. Нажмите Ctrl+C для остановки." << std::endl;
}

void Server::acceptLoop() {
    logger_ptr->write_log(log_location, "[INFO] [Server] Вход в цикл принятия соединений...");
    while (m_is_running) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(server_socket_fd, (struct sockaddr*)&client_addr, &client_len);

        if (client_socket < 0) {
          
            if (m_is_running) {
                 logger_ptr->write_log(log_location, "[ERROR] [Server] accept() завершился с ошибкой.");
            }
            continue;
        }

 
        cleanup_finished_threads();
        
        if (active_clients >= MAX_CLIENTS) {
            logger_ptr->write_log(log_location, "[WARN] [Server] Достигнут лимит клиентов. Соединение отклонено.");
            std::cout << "[WARN] [Server] Отклонено новое соединение: достигнут лимит клиентов." << std::endl;
            ProtocolUtils::send_formatted_message(client_socket, "CONN_REJECT", "server", -1, "Сервер занят, попробуйте позже.");
            close(client_socket);
            continue;
        }

        auto handler = std::make_shared<ClientHandler>(client_socket, client_addr, 
                                                       auth_service_ptr, signing_service_ptr, 
                                                       logger_ptr, log_location, active_clients);

        {
          
            std::lock_guard<std::mutex> lock(m_threads_mutex);
           
            m_threads.emplace_back([handler]() {
                handler->run();
            });
        }
    }
}


void Server::cleanup_finished_threads() {
    std::lock_guard<std::mutex> lock(m_threads_mutex);
    for(auto it = m_threads.begin(); it != m_threads.end(); ) {
        if (it->joinable()) {
        }   
        ++it; 
    }
}