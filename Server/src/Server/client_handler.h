#pragma once

#include <string>
#include <memory>
#include <atomic>
#include <netinet/in.h>

// Зависимости от сервисов, которые будут использоваться
#include "../Auth_reg/auth_service.h"
#include "../Signing/signing_service.h"
#include "../Logger/logger.h"

// Класс для управления жизненным циклом счетчика клиентов (RAII)
class ClientConnectionManager {
public:
    explicit ClientConnectionManager(std::atomic<int>& counter);
    ~ClientConnectionManager();
private:
    std::atomic<int>& client_counter;
};


class ClientHandler {
public:
    ClientHandler(int socket, sockaddr_in addr,
                  std::shared_ptr<AuthService> auth,
                  std::shared_ptr<SigningService> signing,
                  std::shared_ptr<logger> logger_instance,
                  const std::string& log_path,
                  std::atomic<int>& client_counter);

    // Точка входа, которая будет выполняться в новом потоке
    void run();

private:
    // Основная логика обработки
    void processRequests();

    // Методы для обработки конкретных операций
    void handleSignOperation();
    void handleGetPublicKeyOperation();

    int socket_fd;
    std::string client_ip_str;
    std::string client_id_str;
    std::string log_location;
    
    // Указатели на общие сервисы
    std::shared_ptr<AuthService> auth_service;
    std::shared_ptr<SigningService> signing_service;
    std::shared_ptr<logger> logger_ptr;
    
    // Менеджер соединения, использующий RAII
    ClientConnectionManager connection_manager;
};