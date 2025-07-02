#include "signing_service.h"

#include "../Rsa/rsa_crypto.h"
#include <cstdlib>
#include <iostream> 
#include <vector>

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
        
       
        const char* keygen_command = "./src/Signing/keygen";
        
        std::cout << " -> Попытка запустить внешнюю утилиту для генерации ключей '" << keygen_command << "'..." << std::endl;
        
        int result = system(keygen_command);
        
        if (result == 0) { 
            std::cout << "\n[INFO] [SigningService] Утилита генерации ключей успешно выполнена." << std::endl;
        } else {
            std::cerr << "\n[ERROR] [SigningService] Не удалось выполнить утилиту генерации ключей." << std::endl;
            std::cerr << "         Убедитесь, что Makefile корректно собирает утилиту по пути 'src/Signing/keygen'." << std::endl;
        }

        throw SigningServiceError("Инициализация прервана. Ключи отсутствовали и/или были сгенерированы. Пожалуйста, перезапустите сервер.");
    }
}




std::string SigningService::signHash(const std::string& hex_hash) const {
    if (!keys_are_loaded) {
        throw SigningServiceError("Невозможно подписать хеш: ключи не были загружены.");
    }

    std::cout << "[INFO] [SigningService] Начало процесса подписи для хеша: " << hex_hash << std::endl;

    std::vector<unsigned char> byte_vector = hexStringToBytes(hex_hash);

    BigInt hash_as_bigint = fromBytes(byte_vector);

    BigInt signature = rsa_mod_exp(hash_as_bigint, d_key, n_key);
    
    std::string signature_hex = signature.toHexString();
    
    std::cout << "[INFO] [SigningService] Сгенерирована подпись: " << signature_hex << std::endl;

    return signature_hex;
}


std::string SigningService::getPublicKeyN_Hex() const {
    if (!keys_are_loaded) {
        throw SigningServiceError("Невозможно получить ключ N: ключи не были загружены.");
    }
    return n_key.toHexString();
}

std::string SigningService::getPublicKeyE_Hex() const {
    if (!keys_are_loaded) {
        throw SigningServiceError("Невозможно получить ключ E: ключи не были загружены.");
    }
    return e_key.toHexString();
}