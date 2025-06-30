#pragma once

#include <string>
#include <atomic>
#include <memory>
#include <netinet/in.h> // Для sockaddr_in

// Зависимости от новых модулей-сервисов
#include "../Logger/logger.h"
#include "../Base/database.h" // Используем ваше имя класса 'base'
#include "../Auth_reg/auth_service.h"
#include "../Signing/signing_service.h"
#include "../Error/error.h"
#include "../Protocol_utils/protocol_utils.h"
class Server {
public:
    /**
     * @brief Конструктор сервера.
     * @param port Порт, на котором сервер будет слушать.
     * @param log_path Путь к лог-файлу.
     */
    Server(uint16_t port, const std::string& log_path);

    /**
     * @brief Запускает сервер и входит в цикл принятия соединений.
     */
    void run();

private:
    /**
     * @brief Выполняет начальную настройку сокета (socket, bind, listen).
     */
    void setup();

    /**
     * @brief Главный цикл, принимающий новые клиентские соединения.
     */
    void acceptLoop();

    // Конфигурация и состояние сервера
    uint16_t port;
    int server_socket_fd = -1;
    std::string log_location;
    std::atomic<int> active_clients{0};
    const int MAX_CLIENTS = 3; // Лимит одновременных клиентов

    // Общие сервисы, которые будут "внедряться" в обработчики клиентов
    std::shared_ptr<logger> logger_ptr;
    std::shared_ptr<base> db_ptr;
    std::shared_ptr<AuthService> auth_service_ptr;
    std::shared_ptr<SigningService> signing_service_ptr;
};