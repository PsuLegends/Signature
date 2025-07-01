// Файл: Server/server.h
#pragma once

#include <string>
#include <atomic>
#include <memory>
#include <vector>     // Для хранения потоков
#include <thread>     // Для std::thread
#include <mutex>      // Для защиты вектора потоков
#include <netinet/in.h>

// Зависимости от сервисов
#include "../Logger/logger.h"
#include "../Base/database.h"
#include "../Auth_reg/auth_service.h"
#include "../Signing/signing_service.h"
#include "../Error/error.h"

class Server {
public:
    Server(uint16_t port, const std::string& log_path);
    ~Server();
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    void run();

private:
    void setup();
    void acceptLoop();
    void cleanup_finished_threads();
    uint16_t port;
    int server_socket_fd = -1;
    std::string log_location;
    std::atomic<int> active_clients{0};
    const int MAX_CLIENTS = 10; 
    std::vector<std::thread> m_threads;
    std::mutex m_threads_mutex;
    std::atomic<bool> m_is_running{true};
    std::shared_ptr<logger> logger_ptr;
    std::shared_ptr<base> db_ptr;
    std::shared_ptr<AuthService> auth_service_ptr;
    std::shared_ptr<SigningService> signing_service_ptr;
};