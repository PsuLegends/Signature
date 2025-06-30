#include "UI/ui.h" // Предполагаем, что UI остался для парсинга аргументов
#include "Server/server.h" // Включаем новый класс Server
#include "Error/error.h"
#include <iostream>

int main(int argc, char* argv[]) {
    // UI теперь используется только для получения начальных параметров
    UI interface(argc, argv);
    uint16_t port = interface.get_port();
    std::string log_file_path = interface.get_log_loc();

    try {
        // Создаем единственный экземпляр Сервера
        Server server(port, log_file_path);
        // Метод run() теперь содержит бесконечный главный цикл
        server.run(); 
    } catch (const std::exception& e) {
        // Ловим любые критические исключения во время запуска
        std::cerr << "[FATAL] Не удалось запустить сервер: " << e.what() << std::endl;
        return 1; // Выход с кодом ошибки
    }

    return 0; // Эта точка никогда не будет достигнута для сервера, работающего бесконечно
}