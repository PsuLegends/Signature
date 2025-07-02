#include "UI/ui.h"
#include "App_logic/AppLogic.h"
#include "Error/error.h" 
#include "Logger/logger.h"
#include <iostream>
#include <memory>

int main(int argc, char* argv[]) {
    try {

        UI cmd_line_interface(argc, argv);

        std::string ip = cmd_line_interface.get_serv_ip();
        uint16_t port = cmd_line_interface.get_port();
        std::string username = cmd_line_interface.get_username();
        std::string password = cmd_line_interface.get_password();
        uint operation_code = cmd_line_interface.get_op();

        std::string log_file_path = "client_log.txt"; 
        std::shared_ptr<logger> app_logger = std::make_shared<logger>();

        AppLogic application(ip, port, username, password, app_logger, log_file_path);

        if (operation_code == 1) {

            application.run_login_flow();
        } else if (operation_code == 0) {
            application.run_registration_flow();
        } else {
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
