#include "logger.h"
int logger::write_log(std::string log_loc, std::string message)
{
    if (!boost::filesystem::exists(log_loc))
    {
        std::cerr << "Такого лог файла не существует: " << log_loc << std::endl;
        throw critical_error("Не удалось открыть лог файл");
    }
    std::lock_guard<std::mutex> lock(mtx);
    std::ofstream log_file(log_loc, std::ios::app | std::ios::out);
    if (!log_file.is_open())
    {
        std::cerr << "Не удалось открыть лог файл для записи: " << log_loc << std::endl;
        throw critical_error("Не удалось открыть лог файл");
    }
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::string time_str = std::ctime(&t);
    if (!time_str.empty() && time_str.back() == '\n')
    {
        time_str.pop_back();
    }
    log_file << time_str << " / " << message << '\n';
    log_file.flush();

    return 0;
}