// Файл: App_logic/AppLogic.h
#pragma once

#include <string>
#include <memory> // для std::unique_ptr и std::shared_ptr

// Включаем интерфейсы всех модулей, которыми будем управлять
#include "../Network/NetworkClient.h"
#include "../Service/SignatureService.h"
#include "../UI/InteractiveConsole.h"
#include "../Logger/logger.h"
#include "../Rsa/rsa_crypto.h" // Для типа BigInt

/**
 * @class AppLogic
 * @brief Главный класс-координатор, управляющий всей логикой клиентского приложения.
 *
 * Связывает воедино сетевое взаимодействие, криптографические сервисы и
 * пользовательский интерфейс для выполнения сценариев регистрации,
 * аутентификации, запроса и проверки подписей.
 */
class AppLogic {
public:
    /**
     * @brief Конструктор главного контроллера приложения.
     *
     * Принимает все необходимые данные и зависимости для работы.
     * @param ip IP-адрес сервера.
     * @param port Порт сервера.
     * @param username Имя пользователя для аутентификации.
     * @param password Пароль пользователя.
     * @param logger_instance Указатель на общий экземпляр логгера.
     * @param log_path Путь к файлу логов.
     */
    AppLogic(
        const std::string& ip,
        uint16_t port,
        const std::string& username,
        const std::string& password,
        std::shared_ptr<logger> logger_instance,
        const std::string& log_path
    );
    
    // --- ОСНОВНЫЕ СЦЕНАРИИ ЗАПУСКА ---
    
    /**
     * @brief Запускает сценарий аутентификации и входа в систему.
     * 
     * Выполняет подключение к серверу, аутентификацию по протоколу
     * Challenge-Response и, в случае успеха, входит в основной цикл
     * взаимодействия с пользователем.
     */
    void run_login_flow();

    /**
     * @brief Запускает сценарий регистрации нового пользователя.
     *
     * Выполняет подключение к серверу и отправляет данные для регистрации.
     * После выполнения операции (успешной или нет) приложение завершает работу.
     */
    void run_registration_flow();

private:
    // --- Основные этапы работы ---

    /**
     * @brief Выполняет аутентификацию по протоколу Challenge-Response.
     * @return true в случае успеха, false в противном случае.
     */
    bool perform_authentication();

    /**
     * @brief Главный цикл, в котором отображается меню и обрабатывается выбор пользователя.
     */
    void main_loop();

    // --- Обработчики команд из меню ---

    /**
     * @brief Обрабатывает полный сценарий "Запрос подписи для файла".
     */
    void handle_signing_request();

    /**
     * @brief Обрабатывает полный сценарий "Проверка подписи локально".
     */
    void handle_verification_request();
    
    // --- Вспомогательные рабочие процессы ---

    /**
     * @brief Запрашивает и получает с сервера публичный ключ (компоненты N и E).
     * @param out_n Ссылка для сохранения компонента N.
     * @param out_e Ссылка для сохранения компонента E.
     * @return true в случае успеха, false при ошибке.
     */
    bool request_public_key(BigInt& out_n, BigInt& out_e);
    
    // --- Состояние и зависимости ---

    // Данные для сессии
    std::string m_server_ip;
    uint16_t m_server_port;
    std::string m_user_name;
    std::string m_user_password;
    std::string m_log_path;

    // Модули-исполнители
    std::unique_ptr<NetworkClient> m_network;
    SignatureService m_signature_service;
    InteractiveConsole m_console;
    std::shared_ptr<logger> m_logger;
};