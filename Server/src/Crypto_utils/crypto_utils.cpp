#include "crypto_utils.h"

// --- Заголовочные файлы Crypto++ ---
// Для хеширования (SHA-256)
#include "cryptopp/sha.h"

// Для генерации случайных чисел
#include "cryptopp/osrng.h" // AutoSeededRandomPool

// Для кодирования/декодирования и работы с потоками данных
#include "cryptopp/filters.h" // StringSource, HashFilter, ...
#include "cryptopp/hex.h"     // HexEncoder
#include "cryptopp/secblock.h" // SecByteBlock


namespace CryptoUtils {

// Реализация функции хеширования
std::string generate_hash(const std::string& input) {
    // 1. Создаем объект алгоритма хеширования SHA-256.
    CryptoPP::SHA256 hash_algorithm;

    // 2. Создаем строку, которая будет хранить результат в виде дайджеста.
    std::string digest;

    // 3. Создаем "конвейер" для обработки данных:
    //    - StringSource: Источник данных - наша входная строка 'input'.
    //    - HashFilter: Фильтр, который применяет к данным 'hash_algorithm'.
    //    - HexEncoder: Кодировщик, который преобразует бинарный дайджест в HEX-строку.
    //    - StringSink: "Приемник" данных, который помещает результат в строку 'digest'.
    //    Параметр 'true' в StringSource означает "putNextMessage".
    CryptoPP::StringSource(input, true, 
        new CryptoPP::HashFilter(hash_algorithm,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest)
            )
        )
    );

    return digest;
}


// Реализация функции генерации случайной строки
std::string generate_random_hex_string(size_t byte_length) {
    // 1. Создаем объект криптографически стойкого генератора псевдослучайных чисел (CSPRNG).
    //    AutoSeededRandomPool автоматически "засеивается" энтропией из операционной системы,
    //    что делает его непредсказуемым.
    CryptoPP::AutoSeededRandomPool prng;

    // 2. Создаем безопасный блок байт (SecByteBlock) для хранения случайных данных.
    //    SecByteBlock автоматически обнуляет память при уничтожении, чтобы
    //    предотвратить утечку чувствительных данных.
    CryptoPP::SecByteBlock random_bytes(byte_length);
    
    // 3. Заполняем блок случайными данными.
    prng.GenerateBlock(random_bytes, random_bytes.size());

    // 4. Кодируем сырые байты в шестнадцатеричную строку.
    std::string hex_encoded_string;
    CryptoPP::StringSource(random_bytes, random_bytes.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(hex_encoded_string)
        )
    );

    return hex_encoded_string;
}

} // namespace CryptoUtils