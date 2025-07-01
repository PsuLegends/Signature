#include "signing_service.h"

// Подключаем наши утилитарные функции для RSA
// Путь нужно будет скорректировать под вашу структуру.
#include "../Rsa/rsa_crypto.h"
#include <cstdlib>
#include <iostream> // для вывода в консоль
#include <vector>

/**
 * @brief Конструктор сервиса подписи. Сразу же пытается загрузить ключи.
 */
SigningService::SigningService(const std::string& private_key_path,
                               const std::string& public_key_n_path,
                               const std::string& public_key_e_path)
{
    try {
        std::cout << "[INFO] [SigningService] Проверка и загрузка ключей..." << std::endl;
        d_key = loadKeyFromFile(private_key_path);
        n_key = loadKeyFromFile(public_key_n_path);
        e_key = loadKeyFromFile(public_key_e_path);
        keys_are_loaded = true;
        std::cout << "[INFO] [SigningService] Ключи успешно загружены." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "\n[WARN] [SigningService] Не удалось загрузить ключи. Причина: " << e.what() << std::endl;
        
        // *** ИСПРАВЛЕННЫЙ ПУТЬ ВЫЗОВА ***
        const char* keygen_command = "./src/Signing/keygen";
        
        std::cout << " -> Попытка запустить внешнюю утилиту для генерации ключей '" << keygen_command << "'..." << std::endl;
        
        // system() будет искать файл по этому пути ОТНОСИТЕЛЬНО того места, где запущен сервер
        int result = system(keygen_command);
        
        if (result == 0) { 
            std::cout << "\n[INFO] [SigningService] Утилита генерации ключей успешно выполнена." << std::endl;
        } else {
            std::cerr << "\n[ERROR] [SigningService] Не удалось выполнить утилиту генерации ключей." << std::endl;
            std::cerr << "         Убедитесь, что Makefile корректно собирает утилиту по пути 'src/Signing/keygen'." << std::endl;
        }

        // Бросаем исключение, чтобы сервер в любом случае завершил работу
        throw SigningServiceError("Инициализация прервана. Ключи отсутствовали и/или были сгенерированы. Пожалуйста, перезапустите сервер.");
    }
}



/**
 * @brief Подписывает предоставленный хеш.
 */
std::string SigningService::signHash(const std::string& hex_hash) const {
    if (!keys_are_loaded) {
        throw SigningServiceError("Невозможно подписать хеш: ключи не были загружены.");
    }

    std::cout << "[INFO] [SigningService] Начало процесса подписи для хеша: " << hex_hash << std::endl;

    // 1. Конвертируем полученный HEX-хеш в вектор байт
    std::vector<unsigned char> byte_vector = hexStringToBytes(hex_hash);

    // 2. Преобразуем вектор байт в объект BigInt
    BigInt hash_as_bigint = fromBytes(byte_vector);

    // 3. Создаем подпись (шифруем хеш с помощью закрытого ключа d и модуля n)
    BigInt signature = rsa_mod_exp(hash_as_bigint, d_key, n_key);
    
    // 4. Конвертируем объект подписи BigInt в HEX-строку для возврата
    std::string signature_hex = signature.toHexString();
    
    std::cout << "[INFO] [SigningService] Сгенерирована подпись: " << signature_hex << std::endl;

    return signature_hex;
}

/**
 * @brief Возвращает компонент N публичного ключа.
 */
std::string SigningService::getPublicKeyN_Hex() const {
    if (!keys_are_loaded) {
        throw SigningServiceError("Невозможно получить ключ N: ключи не были загружены.");
    }
    return n_key.toHexString();
}

/**
 * @brief Возвращает компонент E публичного ключа.
 */
std::string SigningService::getPublicKeyE_Hex() const {
    if (!keys_are_loaded) {
        throw SigningServiceError("Невозможно получить ключ E: ключи не были загружены.");
    }
    return e_key.toHexString();
}