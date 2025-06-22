#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <cstdint>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <random>

using Limb = uint64_t;

struct BigInt {
    std::vector<Limb> limbs;
    /*
    Конструктор — это функция, которая вызывается, когда вы создаете новый объект (переменную) этого типа.
    Его задача — "построить" объект и привести его в рабочее, осмысленное состояние.

    Имя конструктора всегда совпадает с именем класса/структуры.

    BigInt(): Это объявление конструктора, который не принимает никаких аргументов.
    : limbs{0}: Это называется список инициализации членов. (из чего состоит)
    тут создано как вектор типа uint64_t с начальным значением 0.
    {}: Это тело конструктора. В данном случае оно пустое, потому что всю работу мы сделали в списке инициализации.
    */
   BigInt() : limbs{0} {}

    BigInt(uint64_t value) {
       // Если стандартный конструктор уже создал {0}, очистим это.
       if (limbs.size() == 1 && limbs[0] == 0) {
           limbs.clear();
       }
       limbs.push_back(value);
       // Если передали 0, а вектор был пуст, нужно добавить 0.
       if (limbs.empty() && value == 0) {
           limbs.push_back(0);
       }
   }
   /*
    Конструктор BigInt(uint64_t value): Это объявление конструктора, который принимает один аргумент типа uint64_t.
   */

  // Убирает ведущие нули, чтобы вектор был каноничным
    void normalize() {
        while (limbs.size() > 1 && limbs.back() == 0) {
            limbs.pop_back();
        }
    }

    // Метод для проверки на ноль
    bool isZero() const {
        return limbs.size() == 1 && limbs[0] == 0;
    }

    // Метод для печати числа в 16-ричном виде
    void printHex(const std::string& label = "") const {
        if (!label.empty()) {
            std::cout << label;
        }

        if (isZero()) {
            std::cout << "0x0" << std::endl;
            return;
        }
        
        std::cout << "0x";
        std::cout << std::hex << limbs.back();
        for (int i = limbs.size() - 2; i >= 0; --i) {
            std::cout << std::setw(16) << std::setfill('0') << limbs[i];
        }
        std::cout << std::dec << std::endl;
    }

    std::string toHexString() const {
        std::ostringstream oss;
        oss << std::hex << std::uppercase << limbs.back();
        for (int i = limbs.size() - 2; i >= 0; --i) {
            oss << std::setw(16) << std::setfill('0') << limbs[i];
        }
        return oss.str();
    }
};

bool isPrimeDigit(const std::string& hexStr, int rounds = 64) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* bn = BN_new();
    bool is_prime = false;

    if (!BN_hex2bn(&bn, hexStr.c_str())) {
        std::cerr << "❌ Erroe: couldn't convert from HEX in BIGNUM!" << std::endl;
    } else {
        int result = BN_is_prime_ex(bn, rounds, ctx, nullptr);
        if (result == 1) {
            is_prime = true;
        } else if (result == 0) {
            std::cerr << "❌ Error: nomber in not prime!" << std::endl;
        } else {
            std::cerr << "⚠️ Simplicity unpacking error." << std::endl;
        }
    }

    BN_free(bn);
    BN_CTX_free(ctx);
    return is_prime;
}

BigInt generatePrimeCandidate(size_t len) {
    if (len < 2) return BigInt(0); // Возвращаем BigInt, созданный из нуля
    
    size_t blockCount = (len + 63) / 64;

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::vector<uint64_t> digit_vec(blockCount);
    for (size_t i = 0; i < blockCount; i++) {
        digit_vec[i] = dis(gen);
    }

    size_t lastBlockIndex = (len - 1) / 64;
    size_t bitInLastBlock = (len - 1) % 64;
    digit_vec[lastBlockIndex] |= (1ULL << bitInLastBlock);
    
    digit_vec[0] |= 1ULL;

    BigInt result;            // Создаем пустой объект BigInt
    result.limbs = digit_vec; // Присваиваем его внутреннему полю limbs значения из digit_vec

    return result;
}

BigInt generatePrime(size_t bitLength, int rounds) {
    while (true) {
        BigInt candidate = generatePrimeCandidate(bitLength);
        std::string hexStr = candidate.toHexString();
        if (isPrimeDigit(hexStr, rounds)) {
            return candidate;
        }
    }
}

// Запись ключа в бинарный файл
void saveKeyToFile(const std::string& filename, const BigInt& key) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Не удалось открыть файл для записи: " + filename);
    }

    uint64_t size = key.limbs.size();
    out.write(reinterpret_cast<const char*>(&size), sizeof(size));
    out.write(reinterpret_cast<const char*>(key.limbs.data()), size * sizeof(uint64_t));
    out.close();
}

// Чтение ключа из бинарного файла
BigInt loadKeyFromFile(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Не удалось открыть файл для чтения: " + filename);
    }

    uint64_t size = 0;
    in.read(reinterpret_cast<char*>(&size), sizeof(size));
    if (size == 0) {
        throw std::runtime_error("Некорректный размер ключа в файле: " + filename);
    }

    BigInt key;
    key.limbs.resize(size);
    in.read(reinterpret_cast<char*>(key.limbs.data()), size * sizeof(uint64_t));
    in.close();

    return key;
}

struct RSAKeyPair {
    BigInt p, q, n, phi, e, d;

    RSAKeyPair(size_t bitLength) {
        // 1. Генерация простых p и q
        std::cout << "🧪 Generating p..." << std::endl;
        p = generatePrime(bitLength / 2, 64);
        std::cout << "🧪 Generating q..." << std::endl;
        q = generatePrime(bitLength / 2, 64);

        // 2. Вычисляем n = p * q
        BIGNUM *bn_p = nullptr, *bn_q = nullptr, *bn_n = BN_new();
        BN_hex2bn(&bn_p, p.toHexString().c_str());
        BN_hex2bn(&bn_q, q.toHexString().c_str());
        BN_mul(bn_n, bn_p, bn_q, BN_CTX_new());

        char* n_str = BN_bn2hex(bn_n);
        n = BigInt(); // обнулим
        n.limbs.clear();
        std::string hexN(n_str);
        parseHexToBigInt(hexN, n);

        OPENSSL_free(n_str);
        BN_free(bn_p); BN_free(bn_q); BN_free(bn_n);

        // 3. phi = (p-1)*(q-1)
        BigInt p1 = subtractOne(p);
        BigInt q1 = subtractOne(q);
        BigInt phi_big = multiplyBigInts(p1, q1);
        phi = phi_big;

        // 4. e = 65537
        e = BigInt(65537);

        // 5. d = e^(-1) mod phi
        d = modInverse(e, phi);
    }

    void print() const {
        p.printHex("p: ");
        q.printHex("q: ");
        n.printHex("n (modulus): ");
        phi.printHex("phi: ");
        e.printHex("e (public exponent): ");
        d.printHex("d (private exponent): ");
    }

private:
    BigInt subtractOne(const BigInt& a) {
        BIGNUM* bn = nullptr;
        BN_hex2bn(&bn, a.toHexString().c_str());
        BN_sub_word(bn, 1);
        char* s = BN_bn2hex(bn);
        BigInt result;
        parseHexToBigInt(s, result);
        OPENSSL_free(s);
        BN_free(bn);
        return result;
    }

    BigInt multiplyBigInts(const BigInt& a, const BigInt& b) {
        BIGNUM *bn_a = nullptr, *bn_b = nullptr, *bn_r = BN_new();
        BN_hex2bn(&bn_a, a.toHexString().c_str());
        BN_hex2bn(&bn_b, b.toHexString().c_str());
        BN_mul(bn_r, bn_a, bn_b, BN_CTX_new());
        char* s = BN_bn2hex(bn_r);
        BigInt result;
        parseHexToBigInt(s, result);
        OPENSSL_free(s);
        BN_free(bn_a); BN_free(bn_b); BN_free(bn_r);
        return result;
    }

    BigInt modInverse(const BigInt& a, const BigInt& mod) {
        BIGNUM *bn_a = nullptr, *bn_mod = nullptr;
        BN_hex2bn(&bn_a, a.toHexString().c_str());
        BN_hex2bn(&bn_mod, mod.toHexString().c_str());
        BIGNUM* inv = BN_mod_inverse(nullptr, bn_a, bn_mod, BN_CTX_new());

        char* s = BN_bn2hex(inv);
        BigInt result;
        parseHexToBigInt(s, result);
        OPENSSL_free(s);
        BN_free(bn_a); BN_free(bn_mod); BN_free(inv);
        return result;
    }

    void parseHexToBigInt(const std::string& hex, BigInt& target) {
        target.limbs.clear();
        std::string hexCopy = hex;
        if (hexCopy.size() % 16 != 0) {
            hexCopy = std::string(16 - hexCopy.size() % 16, '0') + hexCopy;
        }

        for (size_t i = 0; i < hexCopy.size(); i += 16) {
            std::string part = hexCopy.substr(i, 16);
            uint64_t limb = std::stoull(part, nullptr, 16);
            target.limbs.insert(target.limbs.begin(), limb); // от младшего к старшему
        }
    }
};

void print_hash(const std::vector<unsigned char>& hash) {
    for (unsigned char byte : hash) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << std::dec << std::endl;
}

std::vector<unsigned char> sha256_hash_file(const std::string& filename) {
    const size_t buffer_size = 4096; // читаем порциями, чтобы не загружать всё в память
    std::vector<unsigned char> buffer(buffer_size);

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Couldn't open the file: " + filename);
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error("Error creating the EVP context");
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Hashing initialization error");
    }

    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer_size);
        std::streamsize bytes_read = file.gcount();
        if (bytes_read > 0) {
            if (1 != EVP_DigestUpdate(mdctx, buffer.data(), bytes_read)) {
                EVP_MD_CTX_free(mdctx);
                throw std::runtime_error("Hash update error");
            }
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Hash finalizing error");
    }

    EVP_MD_CTX_free(mdctx);

    return std::vector<unsigned char>(hash, hash + hash_len);
} 

BigInt rsa_mod_exp(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
    BIGNUM *bn_base = nullptr, *bn_exp = nullptr, *bn_mod = nullptr, *bn_result = BN_new();
    BN_hex2bn(&bn_base, base.toHexString().c_str());
    BN_hex2bn(&bn_exp, exponent.toHexString().c_str());
    BN_hex2bn(&bn_mod, modulus.toHexString().c_str());

    BN_CTX* ctx = BN_CTX_new();
    BN_mod_exp(bn_result, bn_base, bn_exp, bn_mod, ctx);

    char* result_str = BN_bn2hex(bn_result);
    BigInt result;
    result.limbs.clear();

    std::string hexStr(result_str);
    if (hexStr.size() % 16 != 0) {
        hexStr = std::string(16 - hexStr.size() % 16, '0') + hexStr;
    }
    for (size_t i = 0; i < hexStr.size(); i += 16) {
        std::string part = hexStr.substr(i, 16);
        uint64_t limb = std::stoull(part, nullptr, 16);
        result.limbs.insert(result.limbs.begin(), limb);
    }

    OPENSSL_free(result_str);
    BN_free(bn_base); BN_free(bn_exp); BN_free(bn_mod); BN_free(bn_result);
    BN_CTX_free(ctx);

    return result;
}

BigInt fromBytes(const std::vector<unsigned char>& bytes) {
    BigInt result;
    result.limbs.clear();
    
    size_t total = bytes.size();
    for (size_t i = 0; i < total; i += 8) {
        uint64_t limb = 0;
        for (size_t j = 0; j < 8 && (i + j) < total; ++j) {
            limb |= static_cast<uint64_t>(bytes[total - 1 - (i + j)]) << (8 * j);
        }
        result.limbs.push_back(limb);
    }
    result.normalize();
    return result;
}

int main() {
    size_t keySize = 2048;
    std::string filename = "Podpis.odt";

    std::cout << "🔐 RSA key generation (" << keySize << " bit)..." << std::endl;

    // Шаг 1: Генерация ключей
    RSAKeyPair generatedKey(keySize);
    generatedKey.print();

    // Шаг 2: Сохраняем ключи в файлы
    saveKeyToFile("private_d.key", generatedKey.d);
    saveKeyToFile("public_n.key", generatedKey.n);
    saveKeyToFile("public_e.key", generatedKey.e);
    std::cout << "💾 Keys saved to files.\n";

    // Шаг 3: Загружаем ключи обратно
    BigInt d, n, e;
    try {
        d = loadKeyFromFile("private_d.key");
        n = loadKeyFromFile("public_n.key");
        e = loadKeyFromFile("public_e.key");
        std::cout << "📥 Keys loaded from files.\n";
    } catch (const std::exception& ex) {
        std::cerr << "❌ Failed to load keys: " << ex.what() << std::endl;
        return 1;
    }

    try {
        // Шаг 4: Хешируем файл
        auto hash = sha256_hash_file(filename);
        std::cout << "📄 Hash of the file " << filename << ": ";
        print_hash(hash);

        // Шаг 5: Переводим хеш в BigInt
        BigInt hashInt = fromBytes(hash);

        // Шаг 6: Подпись
        BigInt signature = rsa_mod_exp(hashInt, d, n);
        std::cout << "\n✍️ Signature (in hex): ";
        signature.printHex();

        // Сохраняем подпись
        saveKeyToFile("signature.bin", signature);
        std::cout << "✅ The signature is saved to a file signature.bin\n";

        // Шаг 7: Проверка подписи
        BigInt verifiedHash = rsa_mod_exp(signature, e, n);
        std::cout << "\n🔍 Verified hash: ";
        verifiedHash.printHex();

        std::cout << "\n🎯 Original hash (as BigInt): ";
        hashInt.printHex();

        if (verifiedHash.toHexString() == hashInt.toHexString()) {
            std::cout << "\n✅ The signature is confirmed: The hashes match!\n";
        } else {
            std::cout << "\n❌ The signature is not confirmed: The hashes do not match!\n";
        }

    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
