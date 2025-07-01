// Файл: main.cpp
#include "UI/ui.h" // ВАШ класс UI
#include "App_logic/AppLogic.h"
#include "Error/error.h" 
#include "Logger/logger.h" // Нужно для создания логгера
#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {
    try {
        // Шаг 1: Создаем ВАШ объект UI для парсинга аргументов.
        UI cmd_line_interface(argc, argv);

        // Шаг 2: Извлекаем из него все необходимые данные
        std::string ip = cmd_line_interface.get_serv_ip();
        uint16_t port = cmd_line_interface.get_port();
        std::string username = cmd_line_interface.get_username();
        std::string password = cmd_line_interface.get_password();
        uint operation_code = cmd_line_interface.get_op();

        // Шаг 3: Инициализируем зависимости, которые будут общими
        // Например, логгер. Предполагаем, что у вас есть способ получить путь к логам,
        // или зададим его по умолчанию.
        // !!!ВАЖНО!!!: У вас в классе UI нет метода для получения пути к логу, 
        // хотя в Logger он требуется. Давайте временно захардкодим путь.
        std::string log_file_path = "client_log.txt"; 
        // Убедитесь, что этот файл существует, иначе ваш логгер бросит исключение!
        std::shared_ptr<logger> app_logger = std::make_shared<logger>();

        // Шаг 4: Создаем главный логический контроллер
        AppLogic application(ip, port, username, password, app_logger, log_file_path);

        // Шаг 5: ВЫБИРАЕМ И ЗАПУСКАЕМ НУЖНЫЙ СЦЕНАРИЙ
        if (operation_code == 1) {
            // Аутентификация
            application.run_login_flow();
        } else if (operation_code == 0) {
            // Регистрация
            application.run_registration_flow();
        } else {
            // На всякий случай, хотя get_op уже должен был бросить исключение
            std::cerr << "Неизвестный код операции." << std::endl;
        }

    } catch (const po::error& e) {
        std::cerr << "Ошибка в аргументах запуска: " << e.what() << std::endl;
        return 1;
    } catch (const critical_error& e) {
        std::cerr << "Критическая ошибка: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Непредвиденная ошибка: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}