#ifndef RSA_CRYPTO_H
#define RSA_CRYPTO_H

#include <string>
#include <vector>
#include <cstdint>

// Тип для "конечностей" большого числа
using Limb = uint64_t;

/**
 * @brief Структура для представления произвольно больших целых чисел.
 */
struct BigInt
{
    std::vector<Limb> limbs; // Хранятся в little-endian (младшая часть в начале)

    // Конструкторы
    BigInt();
    BigInt(uint64_t value);

    // Методы
    void normalize(); // Удаляет ведущие нули
    bool isZero() const;
    void printHex(const std::string &label = "") const;
    std::string toHexString() const;
};

/**
 * @brief Структура для хранения и генерации пары ключей RSA.
 */
struct RSAKeyPair
{
    BigInt p, q, n, phi, e, d;

    /**
     * @brief Генерирует новую пару ключей RSA заданной длины.
     * @param bitLength Длина ключа в битах (например, 2048).
     */
    RSAKeyPair(size_t bitLength);

    /**
     * @brief Выводит все компоненты ключей в консоль.
     */
    void print() const;
};

// --- Отдельные функции модуля ---

/**
 * @brief Сохраняет ключ (BigInt) в бинарный файл.
 * @param filename Имя файла.
 * @param key Ключ для сохранения.
 */
void saveKeyToFile(const std::string &filename, const BigInt &key);

/**
 * @brief Загружает ключ (BigInt) из бинарного файла.
 * @param filename Имя файла.
 * @return Загруженный ключ типа BigInt.
 */
BigInt loadKeyFromFile(const std::string &filename);

/**
 * @brief Вычисляет хеш SHA-256 для указанного файла.
 * @param filename Путь к файлу.
 * @return Вектор байт, представляющий хеш.
 */
std::vector<unsigned char> sha256_hash_file(const std::string &filename);

/**
 * @brief Выполняет операцию модульного возведения в степень (основа^экспонента % модуль).
 * Это основная операция для шифрования и подписи в RSA.
 * @param base Основание.
 * @param exponent Экспонента (степень).
 * @param modulus Модуль.
 * @return Результат операции (BigInt).
 */
BigInt rsa_mod_exp(const BigInt &base, const BigInt &exponent, const BigInt &modulus);

/**
 * @brief Преобразует вектор байт (например, хеш) в BigInt.
 * @param bytes Входной вектор байт.
 * @return Объект BigInt.
 */
BigInt fromBytes(const std::vector<unsigned char> &bytes);
std::vector<unsigned char> hexStringToBytes(const std::string &hexString);
#endif // RSA_CRYPTO_H