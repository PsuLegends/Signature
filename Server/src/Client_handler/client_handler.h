// Файл: Client_handler/client_handler.h
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


/**
 * @class ClientHandler
 * @brief Обрабатывает одно клиентское соединение в выделенном потоке.
 */
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
    // --- Приватные методы ---
    void processRequests();
    void handleSignOperation();
    void handleGetPublicKeyOperation();

    /**
     * @brief Централизованно отправляет сообщение об ошибке клиенту и логирует ее.
     * @param errorHeader Заголовок сообщения об ошибке (напр., "AUTH_FAIL", "PROTO_ERROR").
     * @param clientMessage Сообщение, которое увидит пользователь клиента.
     * @param logMessage Детальное сообщение для лог-файла сервера.
     */
    void sendErrorAndLog(const std::string& errorHeader, const std::string& clientMessage, const std::string& logMessage);

    // --- Поля класса ---
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