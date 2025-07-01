#pragma once
#include <string>
enum class UserMenuChoice {
    REQUEST_SIGNATURE, // Запросить подпись для файла
    VERIFY_LOCALLY,    // Проверить подпись локально
    EXIT,              // Выход из приложения
    UNKNOWN            // Неверный ввод
};

class InteractiveConsole {
public:
    void show_message(const std::string& msg) const;
    void show_error(const std::string& err_msg) const;
    UserMenuChoice get_user_menu_choice() const;
    std::string ask_filepath(const std::string& prompt) const;
    void display_signature(const std::string& signature_hex) const;
    void display_verification_result(bool is_valid) const;
    
private:
    void clear_input_buffer() const;
};