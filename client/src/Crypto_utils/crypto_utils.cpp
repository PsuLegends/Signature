#include "crypto_utils.h"
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/files.h>
#include <stdexcept>
namespace CryptoUtils
{
    std::string generate_hash(const std::string &input)
    {
        CryptoPP::SHA256 hash_algorithm;
        std::string digest;
        CryptoPP::StringSource(input, true,
                               new CryptoPP::HashFilter(hash_algorithm,
                                                        new CryptoPP::HexEncoder(
                                                            new CryptoPP::StringSink(digest))));
        return digest;
    }

    std::string generate_random_hex_string(size_t byte_length)
    {
        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::SecByteBlock random_bytes(byte_length);
        prng.GenerateBlock(random_bytes, random_bytes.size());

        std::string hex_encoded_string;
        CryptoPP::StringSource(random_bytes, random_bytes.size(), true,
                               new CryptoPP::HexEncoder(
                                   new CryptoPP::StringSink(hex_encoded_string)));
        return hex_encoded_string;
    }
    std::string generate_hash_from_file(const std::string &file_path)
    {
        try
        {
            CryptoPP::SHA256 hash;
            std::string digest;
            CryptoPP::FileSource file(file_path.c_str(), true,
                                      new CryptoPP::HashFilter(hash,
                                                               new CryptoPP::HexEncoder(
                                                                   new CryptoPP::StringSink(digest))));
            return digest;
        }
        catch (const CryptoPP::FileStore::OpenErr &e)
        {
            throw std::runtime_error("Ошибка при открытии файла для хеширования: " + file_path + ". " + e.what());
        }
        catch (const CryptoPP::Exception &e)
        {
            throw std::runtime_error("Ошибка Crypto++ при хешировании файла " + file_path + ": " + e.what());
        }
    }
}