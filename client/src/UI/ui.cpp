// Файл: UI/ui.cpp
#include "ui.h"
#include <iostream>
#include <stdexcept> // для std::invalid_argument
#include <arpa/inet.h> // для inet_pton

UI::UI(int argc, char* argv[]) : desc("Допустимые опции") {
    // 1. Определение опций, которые приложение принимает.
    // Это взято из вашего оригинального кода.
    desc.add_options()
        ("help,h", "Показать это сообщение")
        ("serv_ip,s", po::value<std::string>(), "IP-адрес сервера")
        ("port,p", po::value<uint16_t>(), "Порт сервера (1024-65535)")
        ("operation,o", po::value<uint>(), "Начальная операция: 0 (регистрация) или 1 (аутентификация)")
        ("username,u", po::value<std::string>(), "Имя пользователя")
        ("password,x", po::value<std::string>(), "Пароль пользователя (используем -x для безопасности)");

    // 2. Парсинг. Любые ошибки здесь будут брошены как po::error и пойманы в main.cpp.
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    // 3. Обработка опции --help. Это штатное завершение, а не ошибка.
    if (vm.count("help")) {
        std::cout << desc << std::endl;
        exit(0); // Завершаем программу после вывода справки
    }
    
    // 4. Проверка наличия всех обязательных параметров. Если чего-то нет - бросаем исключение.
    if (!vm.count("serv_ip") || !vm.count("port") || !vm.count("operation") || !vm.count("username") || !vm.count("password")) {
         std::cout << desc << std::endl;
        throw critical_error("Не все обязательные параметры были указаны. Используйте --help для справки.");
    }
}

std::string UI::get_serv_ip() const {
    const std::string ip_str = vm["serv_ip"].as<std::string>();
    
    // Проверяем, что IP-адрес имеет корректный формат IPv4
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip_str.c_str(), &(sa.sin_addr)) != 1) {
        throw critical_error("Указанный IP-адрес '" + ip_str + "' не является корректным IPv4 адресом.");
    }
    return ip_str;
}

uint16_t UI::get_port() const {
    const uint16_t port = vm["port"].as<uint16_t>();
    if (port < 1024 || port > 65535) {
        throw critical_error("Порт " + std::to_string(port) + " находится вне допустимого диапазона [1024-65535].");
    }
    return port;
}

std::string UI::get_username() const {
    // Проверять vm.count() здесь уже не нужно, так как конструктор это сделал.
    return vm["username"].as<std::string>();
}

std::string UI::get_password() const {
    return vm["password"].as<std::string>();
}

uint UI::get_op() const {
    const uint op_code = vm["operation"].as<uint>();
    if (op_code != 0 && op_code != 1) {
        throw critical_error("Код операции должен быть 0 (регистрация) или 1 (аутентификация), но получен: " + std::to_string(op_code));
    }
    return op_code;
}