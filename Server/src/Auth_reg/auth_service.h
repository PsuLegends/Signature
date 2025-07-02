#pragma once
#include <string>
#include <map>
#include <mutex>
#include "../Base/database.h" 
#include "../Logger/logger.h" 
class AuthService {
public:
    AuthService(base& db, logger& logger_instance, const std::string& log_path);
    bool authenticateClient(int socket, const std::string& client_id);
    bool registerClient(int socket, const std::string& client_id, const std::string& client_ip);

private:
    base& db_ref; 
    logger& logger_ref;
    const std::string log_location; 
    std::map<int, std::string> active_challenges;
    std::mutex challenges_mutex;
    void removeChallenge(int socket);
};