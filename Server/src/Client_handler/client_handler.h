#pragma once
#include <string>
#include <memory>
#include <atomic>
#include <netinet/in.h>
#include "../Auth_reg/auth_service.h"
#include "../Signing/signing_service.h"
#include "../Logger/logger.h"
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
    void run();

private:
    void processRequests();
    void handleSignOperation();
    void handleGetPublicKeyOperation();
    void sendErrorAndLog(const std::string& errorHeader, const std::string& clientMessage, const std::string& logMessage);
    int socket_fd;
    std::string client_ip_str;
    std::string client_id_str;
    std::string log_location;
    std::shared_ptr<AuthService> auth_service;
    std::shared_ptr<SigningService> signing_service;
    std::shared_ptr<logger> logger_ptr;
    ClientConnectionManager connection_manager;
};