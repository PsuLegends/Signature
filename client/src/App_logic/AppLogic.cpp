// Файл: App_logic/AppLogic.cpp
#include "AppLogic.h"

// Включаем все необходимые зависимости
#include "../Crypto_utils/crypto_utils.h"
#include <stdexcept> // Для std::invalid_argument

AppLogic::AppLogic(
    const std::string& ip, 
    uint16_t port, 
    const std::string& username, 
    const std::string& password,
    std::shared_ptr<logger> logger_instance,
    const std::string& log_path
) :
    m_server_ip(ip),
    m_server_port(port),
    m_user_name(username),
    m_user_password(password),
    m_logger(logger_instance),
    m_log_path(log_path)
{
    // Проверяем, что логгер был передан корректно
    if (!m_logger) {
        throw std::invalid_argument("Logger instance in AppLogic cannot be null.");
    }
    // Создаем экземпляр сетевого клиента, передавая ему логгер
    m_network = std::make_unique<NetworkClient>(m_logger, m_log_path);
}

// --- ОСНОВНЫЕ СЦЕНАРИИ ЗАПУСКА ---

void AppLogic::run_login_flow() {
    m_logger->write_log(m_log_path, "[AppLogic] Запуск клиента для пользователя '" + m_user_name + "' в режиме АУТЕНТИФИКАЦИИ.");
    
    // Шаг 1: Подключиться к серверу
    if (!m_network->connect(m_server_ip, m_server_port)) {
        m_console.show_error("Не удалось подключиться к серверу. Подробности в лог-файле.");
        return;
    }
    
    // Шаг 2: Пройти аутентификацию
    if (!perform_authentication()) {
        m_console.show_error("Аутентификация не удалась. Отключение.");
        m_network->disconnect();
        return;
    }

    // Шаг 3: Если все успешно, войти в главный цикл
    main_loop();

    // Шаг 4: После выхода из цикла - отключиться
    m_network->disconnect();
    m_console.show_message("Работа клиента завершена.");
    m_logger->write_log(m_log_path, "[AppLogic] Клиент штатно завершил работу.");
}


void AppLogic::run_registration_flow() {
    m_logger->write_log(m_log_path, "[AppLogic] Запуск клиента для пользователя '" + m_user_name + "' в режиме РЕГИСТРАЦИИ.");

    // Шаг 1: Подключиться к серверу
    if (!m_network->connect(m_server_ip, m_server_port)) {
        m_console.show_error("Не удалось подключиться к серверу.");
        return;
    }

    m_logger->write_log(m_log_path, "[AppLogic] Начало процесса регистрации.");
    
    // Шаг 2: Отправляем начальный запрос на регистрацию с типом "REGISTER"
    if (!m_network->send({ "REGISTER", m_user_name, -1, "" })) {
        m_network->disconnect(); // Ошибка уже залогирована в NetworkClient
        return;
    }
    
    // Шаг 3: Отправляем пароль отдельным сообщением с типом "PASSWORD"
    m_logger->write_log(m_log_path, "[AppLogic] Отправка пароля для регистрации.");
    if (!m_network->send({ "PASSWORD", m_user_name, -1, m_user_password })) {
        m_network->disconnect();
        return;
    }
    
    // Шаг 4: Ожидаем результат регистрации от сервера
    auto reg_result = m_network->receive();
    if (reg_result && reg_result->header == "REG_OK") {
        m_logger->write_log(m_log_path, "[AppLogic] Регистрация успешна.");
        m_console.show_message("Регистрация пользователя '" + m_user_name + "' прошла успешно!");
    } else {
        std::string error_details = reg_result ? reg_result->message : "сервер не отвечает";
        m_logger->write_log(m_log_path, "[AppLogic] Регистрация провалена: " + error_details);
        m_console.show_error("Регистрация не удалась: " + error_details);
    }

    // После регистрации в любом случае отключаемся.
    m_network->disconnect();
}


// --- ПРИВАТНЫЕ МЕТОДЫ-ПОМОЩНИКИ ---

bool AppLogic::perform_authentication() {
    m_logger->write_log(m_log_path, "[AppLogic] Начало аутентификации.");
    
    // 1. Отправляем LOGIN запрос
    if (!m_network->send({ "LOGIN", m_user_name, -1, "" })) return false;

    // 2. Ожидаем CHALLENGE (nonce) от сервера
    auto challenge_msg = m_network->receive();
    if (!challenge_msg || challenge_msg->header != "CHALLENGE") {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка: не получен корректный challenge от сервера.");
        return false;
    }
    const std::string& nonce = challenge_msg->message;

    // 3. Вычисляем ответ: response = HASH( HASH(password) + nonce )
    std::string pass_hash = CryptoUtils::generate_hash(m_user_password);
    std::string response_hash = CryptoUtils::generate_hash(pass_hash + nonce);

    // 4. Отправляем наш ответ (протокол сервера ожидает его сразу после CHALLENGE)
    // Сервер AuthService не проверяет заголовок этого сообщения, поэтому можно использовать любой, например "CHALLENGE_RESPONSE" для ясности в логах.
    if (!m_network->send({ "CHALLENGE_RESPONSE", m_user_name, -1, response_hash })) return false;
    
    // 5. Ожидаем результат аутентификации
    auto auth_result = m_network->receive();
    if (auth_result && auth_result->header == "AUTH_OK") {
        m_logger->write_log(m_log_path, "[AppLogic] Аутентификация успешна.");
        m_console.show_message("Аутентификация прошла успешно!");
        return true;
    } else {
        std::string error_details = auth_result ? auth_result->message : "сервер не отвечает";
        m_logger->write_log(m_log_path, "[AppLogic] Аутентификация провалена: " + error_details);
        return false;
    }
}


void AppLogic::main_loop() {
    bool running = true;
    while (running && m_network->is_connected()) {
        UserMenuChoice choice = m_console.get_user_menu_choice();
        
        switch (choice) {
            case UserMenuChoice::REQUEST_SIGNATURE:
                handle_signing_request();
                break;
            case UserMenuChoice::VERIFY_LOCALLY:
                handle_verification_request();
                break;
            case UserMenuChoice::EXIT:
                m_network->send({ "LOGOUT", m_user_name, -1, "" });
                running = false;
                break;
            case UserMenuChoice::UNKNOWN:
            default:
                m_console.show_error("Неверный выбор. Пожалуйста, попробуйте снова.");
                break;
        }
    }
}


void AppLogic::handle_signing_request() {
    m_logger->write_log(m_log_path, "[AppLogic] Пользователь запросил подпись файла.");
    
    std::string file_path = m_console.ask_filepath("Введите полный путь к файлу для подписи: ");
    if (file_path.empty()) return;

    std::string hex_hash;
    try {
        hex_hash = m_signature_service.hash_file(file_path);
        m_logger->write_log(m_log_path, "[AppLogic] Файл '" + file_path + "' успешно хеширован: " + hex_hash);
    } catch (const std::exception& e) {
        m_console.show_error(e.what());
        m_logger->write_log(m_log_path, "[AppLogic] " + std::string(e.what()));
        return;
    }
    
    // Отправляем запрос на подпись и хеш
    if (!m_network->send({ "SIGN_HASH", m_user_name, -1, hex_hash })) return;
    
    auto response = m_network->receive();
    if (response && response->header == "SIGN_SUCCESS") {
        const std::string& signature_hex = response->message;
        m_logger->write_log(m_log_path, "[AppLogic] Получена подпись: " + signature_hex);
        m_console.display_signature(signature_hex);
        
        try {
            m_signature_service.save_signature(file_path, signature_hex);
            m_console.show_message("Подпись сохранена в файл: " + file_path + ".sig");
            m_logger->write_log(m_log_path, "[AppLogic] Подпись успешно сохранена.");
        } catch (const std::exception& e) {
            m_console.show_error(e.what());
            m_logger->write_log(m_log_path, "[AppLogic] Ошибка сохранения подписи: " + std::string(e.what()));
        }
    } else {
        std::string err = response ? response->message : "сервер не отвечает";
        m_console.show_error("Не удалось получить подпись: " + err);
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка получения подписи: " + err);
    }
}


void AppLogic::handle_verification_request() {
    m_logger->write_log(m_log_path, "[AppLogic] Пользователь запросил проверку подписи.");
    
    BigInt n, e;
    if (!request_public_key(n, e)) {
        m_console.show_error("Не удалось получить публичный ключ от сервера.");
        return;
    }
    m_console.show_message("Публичный ключ успешно получен.");

    std::string original_path = m_console.ask_filepath("Введите путь к ОРИГИНАЛЬНОМУ файлу: ");
    if (original_path.empty()) return;

    std::string signature_path = m_console.ask_filepath("Введите путь к файлу ПОДПИСИ (*.sig): ");
    if (signature_path.empty()) return;
    
    try {
        bool is_valid = m_signature_service.verify_signature(original_path, signature_path, n, e);
        m_console.display_verification_result(is_valid);
        m_logger->write_log(m_log_path, "[AppLogic] Проверка подписи завершена. Результат: " + std::string(is_valid ? "УСПЕХ" : "ПРОВАЛ"));
    } catch (const std::exception& e) {
        m_console.show_error(e.what());
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка при верификации: " + std::string(e.what()));
    }
}


bool AppLogic::request_public_key(BigInt& out_n, BigInt& out_e) {
    m_logger->write_log(m_log_path, "[AppLogic] Запрос публичного ключа у сервера.");
    
    if (!m_network->send({ "GET_PUB_KEY", m_user_name, -1, "" })) return false;

    auto n_response = m_network->receive();
    if (!n_response || n_response->header != "PUB_KEY_N") {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка: не получена компонента N ключа.");
        return false;
    }

    auto e_response = m_network->receive();
    if (!e_response || e_response->header != "PUB_KEY_E") {
         m_logger->write_log(m_log_path, "[AppLogic] Ошибка: не получена компонента E ключа.");
        return false;
    }

    try {
        out_n = BigInt::fromHexString(n_response->message);
        out_e = BigInt::fromHexString(e_response->message);
        m_logger->write_log(m_log_path, "[AppLogic] Публичный ключ успешно получен и распарсен.");
        return true;
    } catch (const std::exception& e) {
        m_logger->write_log(m_log_path, "[AppLogic] Ошибка конвертации ключа из HEX: " + std::string(e.what()));
        return false;
    }
}