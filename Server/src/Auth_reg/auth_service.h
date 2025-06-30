// Auth_reg/auth_service.h
#pragma once

#include <string>
#include <map>
#include <mutex>

// Подключаем ваши классы
#include "../Base/base.h" // Класс для работы с БД
#include "../Logger/logger.h" // Класс для логирования

class AuthService {
public:
    // ... (конструктор и другие методы без изменений) ...
    AuthService(base& db, logger& logger_instance, const std::string& log_path);

    /**
     * @brief Проводит аутентификацию клиента.
     * @details Сначала вызывает selectUserByName для загрузки данных в объект БД,
     *          а затем использует getHashedPassword для их получения.
     */
    bool authenticateClient(int socket, const std::string& client_id);

    // ... (метод registerClient без изменений в сигнатуре) ...
    bool registerClient(int socket, const std::string& client_id, const std::string& client_ip);

private:
    base& db_ref; // Используем ваше имя класса 'base'
    logger& logger_ref;
    const std::string log_location; // Путь к файлу логов

    std::map<int, std::string> active_challenges;
    std::mutex challenges_mutex;

    void removeChallenge(int socket);
};