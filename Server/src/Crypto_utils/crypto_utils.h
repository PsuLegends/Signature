// crypto_utils.h
#pragma once
#include <string>

namespace CryptoUtils {
    // Хеширует строку с помощью SHA-256 и возвращает HEX
    std::string generate_hash(const std::string& input);

    // Генерирует крипто-стойкую случайную HEX-строку
    std::string generate_random_hex_string(size_t byte_length);
}