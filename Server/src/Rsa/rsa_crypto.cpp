#include "rsa_crypto.h"
#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <random>

namespace
{

    BigInt bignumToBigInt(const BIGNUM *bn)
    {
        char *hex_str = BN_bn2hex(bn);
        if (!hex_str)
            throw std::runtime_error("BN_bn2hex failed");

        std::string hex(hex_str);
        OPENSSL_free(hex_str);

        BigInt target;
        target.limbs.clear();
        if (hex.empty() || hex == "0")
        {
            return BigInt(0);
        }

        if (hex.size() % 16 != 0)
        {
            hex.insert(0, 16 - (hex.size() % 16), '0');
        }

        for (size_t i = 0; i < hex.size(); i += 16)
        {
            std::string part = hex.substr(i, 16);
            target.limbs.insert(target.limbs.begin(), std::stoull(part, nullptr, 16));
        }
        target.normalize();
        return target;
    }

    BIGNUM *bigIntToBignum(const BigInt &bi)
    {
        BIGNUM *bn = nullptr;
        std::string hex = bi.toHexString();
        BN_hex2bn(&bn, hex.c_str());
        return bn;
    }
    bool isPrime(const BigInt &candidate, int rounds = 64)
    {
        BIGNUM *bn = bigIntToBignum(candidate);
        BN_CTX *ctx = BN_CTX_new();
        int result = BN_is_prime_ex(bn, rounds, ctx, nullptr);
        BN_free(bn);
        BN_CTX_free(ctx);

        if (result < 0)
            throw std::runtime_error("Primality test error");
        return result == 1;
    }

    BigInt generatePrimeCandidate(size_t len)
    {
        if (len < 2)
            return BigInt(0);
        size_t limbCount = (len + 63) / 64;

        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis;

        BigInt result;
        result.limbs.resize(limbCount, 0);
        for (size_t i = 0; i < limbCount; i++)
        {
            result.limbs[i] = dis(gen);
        }

        result.limbs.back() |= (1ULL << ((len - 1) % 64));
        result.limbs[0] |= 1ULL;

        result.normalize();
        return result;
    }

    BigInt generatePrime(size_t bitLength, int rounds)
    {
        while (true)
        {
            BigInt candidate = generatePrimeCandidate(bitLength);
            if (isPrime(candidate, rounds))
            {
                return candidate;
            }
        }
    }

}

BigInt::BigInt() : limbs{0} {}
BigInt::BigInt(uint64_t value)
{
    if (value == 0)
        limbs.push_back(0);
    else
        limbs.push_back(value);
}

void BigInt::normalize()
{
    while (limbs.size() > 1 && limbs.back() == 0)
    {
        limbs.pop_back();
    }
}

bool BigInt::isZero() const
{
    return limbs.size() == 1 && limbs[0] == 0;
}

std::string BigInt::toHexString() const
{
    if (isZero())
        return "0";
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    oss << limbs.back();
    for (int i = limbs.size() - 2; i >= 0; --i)
    {
        oss << std::setw(16) << std::setfill('0') << limbs[i];
    }
    return oss.str();
}

void BigInt::printHex(const std::string &label) const
{
    if (!label.empty())
        std::cout << label;
    std::cout << "0x" << this->toHexString() << std::dec << std::endl;
}

RSAKeyPair::RSAKeyPair(size_t bitLength)
{
    std::cout << "🧪 Generating p..." << std::endl;
    p = generatePrime(bitLength / 2, 64);
    std::cout << "🧪 Generating q..." << std::endl;
    q = generatePrime(bitLength / 2, 64);

    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_p = bigIntToBignum(p);
    BIGNUM *bn_q = bigIntToBignum(q);

    BIGNUM *bn_n = BN_new();
    BN_mul(bn_n, bn_p, bn_q, ctx);
    n = bignumToBigInt(bn_n);

    BIGNUM *bn_p1 = BN_dup(bn_p);
    BN_sub_word(bn_p1, 1);
    BIGNUM *bn_q1 = BN_dup(bn_q);
    BN_sub_word(bn_q1, 1);
    BIGNUM *bn_phi = BN_new();
    BN_mul(bn_phi, bn_p1, bn_q1, ctx);
    phi = bignumToBigInt(bn_phi);

    e = BigInt(65537);
    BIGNUM *bn_e = bigIntToBignum(e);

    BIGNUM *bn_d = BN_mod_inverse(nullptr, bn_e, bn_phi, ctx);
    d = bignumToBigInt(bn_d);

    BN_CTX_free(ctx);
    BN_free(bn_p);
    BN_free(bn_q);
    BN_free(bn_n);
    BN_free(bn_p1);
    BN_free(bn_q1);
    BN_free(bn_phi);
    BN_free(bn_e);
    BN_free(bn_d);
}

void RSAKeyPair::print() const
{
    p.printHex("p: ");
    q.printHex("q: ");
    n.printHex("n (modulus): ");
    phi.printHex("phi: ");
    e.printHex("e (public exponent): ");
    d.printHex("d (private exponent): ");
}

void saveKeyToFile(const std::string &filename, const BigInt &key)
{
    std::ofstream out(filename, std::ios::binary);
    if (!out)
        throw std::runtime_error("Не удалось открыть файл для записи: " + filename);
    uint64_t size = key.limbs.size();
    out.write(reinterpret_cast<const char *>(&size), sizeof(size));
    out.write(reinterpret_cast<const char *>(key.limbs.data()), size * sizeof(Limb));
}

BigInt loadKeyFromFile(const std::string &filename)
{
    std::ifstream in(filename, std::ios::binary);
    if (!in)
        throw std::runtime_error("Не удалось открыть файл для чтения: " + filename);
    uint64_t size = 0;
    in.read(reinterpret_cast<char *>(&size), sizeof(size));
    if (!in || size == 0)
        throw std::runtime_error("Некорректный формат файла: " + filename);
    BigInt key;
    key.limbs.resize(size);
    in.read(reinterpret_cast<char *>(key.limbs.data()), size * sizeof(Limb));
    if (!in)
        throw std::runtime_error("Не удалось прочитать данные ключа из файла: " + filename);
    return key;
}

std::vector<unsigned char> sha256_hash_file(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("Не удалось открыть файл: " + filename);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        throw std::runtime_error("Ошибка создания контекста EVP");
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr))
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Ошибка инициализации хеширования");
    }

    const size_t bufSize = 4096;
    std::vector<char> buffer(bufSize);
    while (file)
    {
        file.read(buffer.data(), bufSize);
        if (file.gcount() > 0)
        {
            if (1 != EVP_DigestUpdate(mdctx, buffer.data(), file.gcount()))
            {
                EVP_MD_CTX_free(mdctx);
                throw std::runtime_error("Ошибка обновления хеша");
            }
        }
    }

    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hash_len = 0;
    if (1 != EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len))
    {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Ошибка финализации хеша");
    }
    hash.resize(hash_len);
    EVP_MD_CTX_free(mdctx);
    return hash;
}

BigInt rsa_mod_exp(const BigInt &base, const BigInt &exponent, const BigInt &modulus)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *bn_base = bigIntToBignum(base);
    BIGNUM *bn_exp = bigIntToBignum(exponent);
    BIGNUM *bn_mod = bigIntToBignum(modulus);
    BIGNUM *bn_res = BN_new();

    BN_mod_exp(bn_res, bn_base, bn_exp, bn_mod, ctx);

    BigInt result = bignumToBigInt(bn_res);

    BN_CTX_free(ctx);
    BN_free(bn_base);
    BN_free(bn_exp);
    BN_free(bn_mod);
    BN_free(bn_res);
    return result;
}

BigInt fromBytes(const std::vector<unsigned char> &bytes)
{
    BIGNUM *bn = BN_bin2bn(bytes.data(), bytes.size(), nullptr);
    if (!bn)
        throw std::runtime_error("Ошибка конвертации байтов в BigInt");
    BigInt result = bignumToBigInt(bn);
    BN_free(bn);
    return result;
}
std::vector<unsigned char> hexStringToBytes(const std::string &hex)
{
    std::string processedHex = hex;
    if (processedHex.rfind("0x", 0) == 0 || processedHex.rfind("0X", 0) == 0)
    {
        processedHex = processedHex.substr(2);
    }

    if (processedHex.length() % 2 != 0)
    {
        throw std::invalid_argument("Шестнадцатеричная строка должна иметь четное количество символов.");
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(processedHex.length() / 2);

    for (size_t i = 0; i < processedHex.length(); i += 2)
    {
        std::string byteString = processedHex.substr(i, 2);
        try
        {
            unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        catch (const std::exception &e)
        {
            throw std::invalid_argument("Строка содержит недопустимые шестнадцатеричные символы: '" + byteString + "'");
        }
    }

    return bytes;
}
BigInt BigInt::fromHexString(const std::string &hexString)
{
    BIGNUM *bn = nullptr;
    std::string processedHex = hexString;
    if (processedHex.rfind("0x", 0) == 0 || processedHex.rfind("0X", 0) == 0)
    {
        processedHex = processedHex.substr(2);
    }

    if (!BN_hex2bn(&bn, processedHex.c_str()))
    {
        if (bn)
            BN_free(bn);
        throw std::runtime_error("Failed to convert hexadecimal string to BIGNUM: " + processedHex);
    }

    BigInt result = bignumToBigInt(bn);

    BN_free(bn);

    return result;
}