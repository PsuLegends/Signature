#include "InteractiveConsole.h"
#include <iostream>
#include <limits> 
void InteractiveConsole::show_message(const std::string& msg) const {
    std::cout << "[INFO] " << msg << std::endl;
}

void InteractiveConsole::show_error(const std::string& err_msg) const {
    std::cerr << "[ОШИБКА] " << err_msg << std::endl;
}
void InteractiveConsole::clear_input_buffer() const {
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

UserMenuChoice InteractiveConsole::get_user_menu_choice() const {
    std::cout << "\n========================================" << std::endl;
    std::cout << "  Главное меню:" << std::endl;
    std::cout << "  1. Запросить подпись для файла" << std::endl;
    std::cout << "  2. Проверить подпись локально" << std::endl;
    std::cout << "  0. Выход" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Ваш выбор -> ";

    int choice = -1;
    std::cin >> choice;
    if (std::cin.fail()) {
        std::cin.clear(); 
        clear_input_buffer(); 
        return UserMenuChoice::UNKNOWN;
    }
    clear_input_buffer(); 
    switch (choice) {
        case 1: return UserMenuChoice::REQUEST_SIGNATURE;
        case 2: return UserMenuChoice::VERIFY_LOCALLY;
        case 0: return UserMenuChoice::EXIT;
        default: return UserMenuChoice::UNKNOWN;
    }
}

std::string InteractiveConsole::ask_filepath(const std::string& prompt) const {
    std::cout << "[ВВОД] " << prompt;
    std::string file_path;
    std::getline(std::cin, file_path);
    if (file_path.empty()) {
        show_error("Путь к файлу не может быть пустым.");
    }
    return file_path;
}
void InteractiveConsole::display_signature(const std::string& signature_hex) const {
    std::cout << "[РЕЗУЛЬТАТ] Получена подпись от сервера:" << std::endl;
    std::cout << "------------------------------------------" << std::endl;
    std::cout << signature_hex << std::endl;
    std::cout << "------------------------------------------" << std::endl;
}
void InteractiveConsole::display_verification_result(bool is_valid) const {
    std::cout << "[РЕЗУЛЬТАТ ПРОВЕРКИ]" << std::endl;
    if (is_valid) {
        std::cout << "  ПОДПИСЬ ВЕРНА: Хеши совпадают." << std::endl;
    } else {
        std::cout << "  ПОДПИСЬ НЕВЕРНА: Хеши не совпадают." << std::endl;
    }
}