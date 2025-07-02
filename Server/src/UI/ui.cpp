#include "ui.h"
#include <boost/program_options.hpp>
namespace po = boost::program_options;
UI::UI(int argc, char* argv[]) {
    desc.add_options()
        ("help,h", "Помощь")  
        ("Log_loc,l", po::value<std::vector<std::string>>()->multitoken(), "Путь для log файла")  
        ("Port,p", po::value<std::vector<uint>>()->multitoken(), "Порт сервера(1025-65534)");  

    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);

        if (vm.count("help") || !vm.count("Log_loc") || !vm.count("Port")) {
            std::cout << desc << std::endl;
            exit(0);
        }

        po::notify(vm);
    } catch (po::error& e) {
        std::cout << e.what() << std::endl;
    }
    catch(critical_error &e){
        std::cout << "Критическая ошибка: " << e.what() << std::endl;
    }
}
uint UI::get_port()
{
    if (vm.count("Port") and !vm["Port"].as<std::vector<uint>>().empty())
    {
        const std::vector<uint> &ports = vm["Port"].as<std::vector<uint>>();
        
        if (ports.back() < 1024)
        {
            std::cout<<"Неверное значение порта"<<std::endl;
            std::cout << desc << std::endl;
            exit(0); 
            return 1;
        }
        if (ports.back() > 65535)
        {
            std::cout<<"Неверное значение порта"<<std::endl;
            std::cout << desc << std::endl;
            exit(0); 
            return 1;
        }

        return ports.back();
    }
    else
    {
        std::cout << desc << std::endl;
        return 1;
    }
}

std::string UI::get_log_loc() {
    if (vm.count("Log_loc")) {
        const std::vector<std::string>& log_loc = vm["Log_loc"].as<std::vector<std::string>>(); 
        return log_loc.back();  
    } else {
        return "";  
    }
}
