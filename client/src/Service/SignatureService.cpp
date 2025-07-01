// Файл: Service/SignatureService.cpp
#include "SignatureService.h"

// --- НЕОБХОДИМЫЕ ВКЛЮЧЕНИЯ ---
#include "../Crypto_utils/crypto_utils.h" // Теперь этот файл полностью определен
#include "../Rsa/rsa_crypto.h"
#include <stdexcept>
#include <algorithm> // для std::transform

// --- Реализация методов ---

std::string SignatureService::hash_file(const std::string& file_path) const {
    // Вызов функции из нашего полностью готового модуля
    return CryptoUtils::generate_hash_from_file(file_path);
}

void SignatureService::save_signature(const std::string& original_file_path, const std::string& signature_hex) const {
    // 1. Конвертируем HEX-строку подписи в объект BigInt
    BigInt signature_as_bigint = BigInt::fromHexString(signature_hex);
    
    // 2. Генерируем имя файла для подписи (например, document.txt -> document.txt.sig)
    std::string signature_filename = original_file_path + ".sig";
    
    // 3. Используем вашу существующую функцию для сохранения
    // `saveKeyToFile` находится в `Rsa/rsa_crypto.cpp`.
    saveKeyToFile(signature_filename, signature_as_bigint);
}

bool SignatureService::verify_signature(
    const std::string& original_file_path,
    const std::string& signature_file_path,
    const BigInt& public_n, 
    const BigInt& public_e
) const {
    try {
        // --- Шаг 1: Вычисляем хеш оригинального файла ---
        std::string original_hash_hex = this->hash_file(original_file_path);
        
        // --- Шаг 2: Загружаем подпись из файла ---
        // `loadKeyFromFile` находится в `Rsa/rsa_crypto.cpp`
        BigInt signature_as_bigint = loadKeyFromFile(signature_file_path);
        
        // --- Шаг 3: Расшифровываем подпись публичным ключом ---
        // `rsa_mod_exp` находится в `Rsa/rsa_crypto.cpp`
        BigInt decrypted_hash_bigint = rsa_mod_exp(signature_as_bigint, public_e, public_n);
        
        // --- Шаг 4: Конвертируем оба результата в HEX-строки и сравниваем ---
        std::string decrypted_hash_hex = decrypted_hash_bigint.toHexString();
        
        // Приводим обе строки к верхнему регистру для надежного сравнения
        std::transform(original_hash_hex.begin(), original_hash_hex.end(), original_hash_hex.begin(), ::toupper);
        std::transform(decrypted_hash_hex.begin(), decrypted_hash_hex.end(), decrypted_hash_hex.begin(), ::toupper);
        
        return original_hash_hex == decrypted_hash_hex;

    } catch (const std::exception& e) {
        // Перехватываем ошибки от нижних уровней (например, "файл не найден")
        // и передаем их наверх в виде одного понятного исключения.
        throw std::runtime_error("Ошибка в процессе верификации: " + std::string(e.what()));
    }
}