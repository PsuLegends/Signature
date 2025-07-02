#pragma once
#include <string>

namespace CryptoUtils {
    std::string generate_hash(const std::string& input);
    std::string generate_random_hex_string(size_t byte_length);
}