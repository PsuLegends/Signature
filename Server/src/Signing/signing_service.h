#pragma once

#include <string>
#include <stdexcept>

// Подключаем наш модуль для работы с RSA.
// Путь нужно будет скорректировать под вашу структуру.
#include "../Rsa/rsa_crypto.h" 

// Определяем кастомное исключение для ошибок сервиса подписи
class SigningServiceError : public std::runtime_error {
public:
    explicit SigningServiceError(const std::string& message) : std::runtime_error(message) {}
};

class SigningService {
public:
    /**
     * @brief Конструктор сервиса подписи.
     * @param private_key_path Путь к файлу с приватным ключом (d).
     * @param public_key_n_path Путь к файлу с компонентом N публичного ключа.
     * @param public_key_e_path Путь к файлу с компонентом E публичного ключа.
     */
    SigningService(const std::string& private_key_path, 
                   const std::string& public_key_n_path, 
                   const std::string& public_key_e_path);

    /**
     * @brief Подписывает предоставленный хеш.
     * @param hex_hash Хеш данных, представленный в виде HEX-строки.
     * @return Электронная подпись в виде HEX-строки.
     * @throw SigningServiceError если ключи не были загружены.
     */
    std::string signHash(const std::string& hex_hash) const;

    /**
     * @brief Возвращает компонент N публичного ключа.
     * @return Компонент N в виде HEX-строки.
     * @throw SigningServiceError если ключи не были загружены.
     */
    std::string getPublicKeyN_Hex() const;

    /**
     * @brief Возвращает компонент E публичного ключа.
     * @return Компонент E в виде HEX-строки.
     * @throw SigningServiceError если ключи не были загружены.
     */
    std::string getPublicKeyE_Hex() const;

private:
    /**
     * @brief Внутренняя функция для загрузки всех ключей с диска.
     * @throw SigningServiceError если какой-либо из файлов ключей не может быть загружен.
     */
    void loadKeys();

    // Хранилища для ключей
    BigInt d_key; // Приватный ключ
    BigInt n_key; // Модуль (часть публичного ключа)
    BigInt e_key; // Экспонента (часть публичного ключа)
    
    // Флаг, показывающий, были ли ключи успешно загружены
    bool keys_are_loaded = false;
};