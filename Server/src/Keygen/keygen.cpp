#include <iostream>
#include <string>
#include <stdexcept>
#include "../Rsa/rsa_crypto.h"

const std::string PRIV_KEY_FILE = "private.key";
const std::string PUB_N_FILE = "public_n.key";
const std::string PUB_E_FILE = "public_e.key";
const size_t KEY_BIT_LENGTH = 2048;

int main()
{
    try
    {
        std::cout << "Утилита для генерации ключевой пары RSA..." << std::endl;
        std::cout << "Длина ключа: " << KEY_BIT_LENGTH << " бит." << std::endl;
        RSAKeyPair key_pair(KEY_BIT_LENGTH);

        std::cout << "\nКлючевая пара успешно сгенерирована." << std::endl;
        key_pair.print();
        std::cout << "\nСохранение ключей в файлы..." << std::endl;
        saveKeyToFile(PRIV_KEY_FILE, key_pair.d);
        std::cout << " -> " << PRIV_KEY_FILE << std::endl;

        saveKeyToFile(PUB_N_FILE, key_pair.n);
        std::cout << " -> " << PUB_N_FILE << std::endl;

        saveKeyToFile(PUB_E_FILE, key_pair.e);
        std::cout << " -> " << PUB_E_FILE << std::endl;

        std::cout << "\nВсе ключи успешно созданы и сохранены в текущей директории." << std::endl;
        std::cout << "Теперь вы можете запустить сервер." << std::endl;

        return 0;
    }
    catch (const std::exception &e)
    {
        std::cerr << "\nКРИТИЧЕСКАЯ ОШИБКА во время генерации ключей: " << e.what() << std::endl;
        return 1;
    }
}