#include "UI/ui.h" 
#include "Server/server.h"
#include "Error/error.h"
#include <iostream>

int main(int argc, char* argv[]) {
  
    UI interface(argc, argv);
    uint16_t port = interface.get_port();
    std::string log_file_path = interface.get_log_loc();

    try {
        
        Server server(port, log_file_path);
        server.run(); 
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] Не удалось запустить сервер: " << e.what() << std::endl;
        return 1; 
    }

    return 0; 
}