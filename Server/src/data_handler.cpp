#include "data_handler.h"
std::vector<std::string> data_handler::get_file_list()
{
    // Создаем вектор для хранения списка файлов
    std::vector<std::string> file_list;

    // Получаем текущий путь выполнения программы
    std::string exe_path = std::filesystem::current_path().string();

    // Перебираем все файлы в директории текущего пути
    for (const auto &entry : std::filesystem::directory_iterator(exe_path))
    {
        // Проверяем, является ли элемент обычным файлом
        if (entry.is_regular_file())
        {
            // Добавляем имя файла в список
            file_list.push_back(entry.path().filename().string());
        }
    }

    // Возвращаем список файлов
    return file_list;
}
