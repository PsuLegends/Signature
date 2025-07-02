#ifndef RSA_CRYPTO_H
#define RSA_CRYPTO_H

#include <string>
#include <vector>
#include <cstdint>

using Limb = uint64_t;

struct BigInt
{
    std::vector<Limb> limbs;

    BigInt();
    BigInt(uint64_t value);
    void normalize();
    bool isZero() const;
    void printHex(const std::string &label = "") const;
    std::string toHexString() const;
    static BigInt fromHexString(const std::string &hexString);
};

struct RSAKeyPair
{
    BigInt p, q, n, phi, e, d;

    RSAKeyPair(size_t bitLength);
    void print() const;
};

void saveKeyToFile(const std::string &filename, const BigInt &key);

BigInt loadKeyFromFile(const std::string &filename);

std::vector<unsigned char> sha256_hash_file(const std::string &filename);

BigInt rsa_mod_exp(const BigInt &base, const BigInt &exponent, const BigInt &modulus);

BigInt fromBytes(const std::vector<unsigned char> &bytes);
std::vector<unsigned char> hexStringToBytes(const std::string &hexString);
#endif