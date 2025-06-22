#include "ui.h"
#include <boost/program_options.hpp>
namespace po = boost::program_options;
UI::UI(int argc, char *argv[])
{
    // Описание параметров командной строки с помощью Boost.Program_options
    desc.add_options()
        ("help,h", "Помощь\nВсе параметры ниже являются обязательными")
        ("serv_ip,s", po::value<std::vector<std::string>>()->multitoken(), "Айпи сервера")
        ("operation, o", po::value<std::vector<uint>>()->multitoken(), "1 - аутентификация, 0 - регистрация")
        ("username, u", po::value<std::vector<std::string>>()->multitoken(), "Имя пользователя")
        ("password, pa", po::value<std::vector<std::string>>()->multitoken(), "Пароль пользователя")
        ("port,p", po::value<std::vector<uint>>()->multitoken(), "Порт сервера");

    // Разбор командной строки и сохранение параметров во внутреннюю структуру vm
    po::store(po::parse_command_line(argc, argv, desc), vm);

    // Проверка обязательных параметров
    if (vm.count("help") or !vm.count("serv_ip") or !vm.count("port")) {
        std::cout << desc << std::endl;  // Вывод справки
        exit(0);  // Завершение программы
    }

    // Применение параметров
    po::notify(vm);
}
// Получение имени пользователя из командной строки
std::string UI::get_username(){
    // Проверяем наличие параметра "username" и непустоту вектора значений
    if (vm.count("username") and !vm["username"].as<std::vector<std::string>>().empty())
    {
        // Получаем вектор имён пользователей и возвращаем последнее введённое значение
        const std::vector<std::string> &username = vm["username"].as<std::vector<std::string>>();
        return username.back();
    }
    else
    {
        // Если имя не указано — выводим справку и вызываем отладчик с ошибкой
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_username()", "Неопределенное значение имени пользователя", "Неопределенная ошибка");
        return "";
    }
}

// Получение типа операции (регистрация или аутентификация)
uint UI::get_op(){
    // Проверяем наличие параметра "operation" и непустоту вектора значений
    if (vm.count("operation") and !vm["operation"].as<std::vector<uint>>().empty())
    {
        const std::vector<uint> &op = vm["operation"].as<std::vector<uint>>();
        // Проверка допустимого значения: 0 (регистрация) или 1 (аутентификация)
        if (op.back()>1 or op.back()<0)
        {
            std::cout << desc << std::endl;
            debugger.show_error_information("Ошибка в get_op()", "Неверный номер операции", "Логическая ошибка");
            return 2; // 2 = ошибка
        }
        return op.back();
    }
    else
    {
        // Если параметр отсутствует — выводим справку и ошибку
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_op()", "Неопределенное значение операции", "Неопределенная ошибка");
        return 2;
    }
}

// Получение пароля
std::string UI::get_password(){
    if (vm.count("password") and !vm["password"].as<std::vector<std::string>>().empty())
    {
        const std::vector<std::string> &password = vm["password"].as<std::vector<std::string>>();
        return password.back(); // возвращаем последний переданный пароль
    }
    else
    {
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_password()", "Неопределенное значение пароля", "Неопределенная ошибка");
        return "";
    }
}

// Получение номера порта
uint UI::get_port()
{
    if (vm.count("port") and !vm["port"].as<std::vector<uint>>().empty())
    {
        const std::vector<uint> &ports = vm["port"].as<std::vector<uint>>();
        
        // Проверка на допустимые значения диапазона портов
        if (ports.back() < 1024)
        {
            std::cout << desc << std::endl;
            debugger.show_error_information("Ошибка в get_port()", "Выбранный порт меньше 1024", "Логическая ошибка");
            return 1;
        }
        if (ports.back() > 65535)
        {
            std::cout << desc << std::endl;
            debugger.show_error_information("Ошибка в get_port()", "Выбранный порт больше 65535", "Логическая ошибка");
            return 1;
        }

        return ports.back();
    }
    else
    {
        // Если порт не передан — выводим справку и сообщение об ошибке
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_port()", "Неопределенное значение порта", "Неопределенная ошибка");
        return 1;
    }
}

// Получение IP-адреса сервера
std::string UI::get_serv_ip()
{
    struct in_addr addr; // Структура для хранения адреса в двоичном виде

    if (vm.count("serv_ip") and !vm["serv_ip"].as<std::vector<std::string>>().empty())
    {
        const std::vector<std::string> &ip_s = vm["serv_ip"].as<std::vector<std::string>>();

        // Проверка корректности формата IP (должен быть IPv4)
        if (inet_pton(AF_INET, ip_s.back().c_str(), &addr) == 0)
        {
            std::cout << desc << std::endl;
            debugger.show_error_information("Ошибка в get_ip()", "ip не соответстует формату ipv4", "Логическая ошибка");
            return "";
        }

        return ip_s.back();
    }
    else
    {
        // Если IP не передан — выводим справку и сообщение об ошибке
        std::cout << desc << std::endl;
        debugger.show_error_information("Ошибка в get_ip()", "Неопределенное значение ip", "Неопределенная ошибка");
        return "";
    }
}