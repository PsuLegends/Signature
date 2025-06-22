#include "logger.h"
int logger::write_log( std::string log_loc,  std::string message) {
    // Проверяем, существует ли лог-файл по указанному пути
    if (!boost::filesystem::exists(log_loc)) {
        std::cerr << "Такого лог файла не существует: " << log_loc << std::endl;
        throw critical_error("Не удалось открыть лог файл");
    }

    // Синхронизируем доступ к логированию
    std::lock_guard<std::mutex> lock(mtx);

    // Открываем файл для дозаписи внутри критической секции
    std::ofstream log_file(log_loc, std::ios::app | std::ios::out);
    if (!log_file.is_open()) {
        std::cerr << "Не удалось открыть лог файл для записи: " << log_loc << std::endl;
        throw critical_error("Не удалось открыть лог файл");
    }

    // Получаем текущее время и форматируем его
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&t);
    if (!time_str.empty() && time_str.back() == '\n') {
        time_str.pop_back();
    }

    // Записываем время и сообщение в лог-файл
    log_file << time_str << " / " << message << '\n';
    log_file.flush();  // сброс буфера
    // Файл автоматически закроется по выходу из scope

    return 0;
}