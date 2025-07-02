#include "crypto_utils.h"
#include "cryptopp/sha.h"
#include "cryptopp/osrng.h"

#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/secblock.h"

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

}