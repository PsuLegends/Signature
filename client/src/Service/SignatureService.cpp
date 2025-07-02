
#include "SignatureService.h"

#include "../Crypto_utils/crypto_utils.h"
#include "../Rsa/rsa_crypto.h"
#include <stdexcept>
#include <algorithm> 
std::string SignatureService::hash_file(const std::string& file_path) const {
    return CryptoUtils::generate_hash_from_file(file_path);
}

void SignatureService::save_signature(const std::string& original_file_path, const std::string& signature_hex) const {
    BigInt signature_as_bigint = BigInt::fromHexString(signature_hex);
    std::string signature_filename = original_file_path + ".sig";
    saveKeyToFile(signature_filename, signature_as_bigint);
}

bool SignatureService::verify_signature(
    const std::string& original_file_path,
    const std::string& signature_file_path,
    const BigInt& public_n, 
    const BigInt& public_e
) const {
    try {
        std::string original_hash_hex = this->hash_file(original_file_path);
        BigInt signature_as_bigint = loadKeyFromFile(signature_file_path);
        BigInt decrypted_hash_bigint = rsa_mod_exp(signature_as_bigint, public_e, public_n);
        std::string decrypted_hash_hex = decrypted_hash_bigint.toHexString();
        std::transform(original_hash_hex.begin(), original_hash_hex.end(), original_hash_hex.begin(), ::toupper);
        std::transform(decrypted_hash_hex.begin(), decrypted_hash_hex.end(), decrypted_hash_hex.begin(), ::toupper);
        return original_hash_hex == decrypted_hash_hex;

    } catch (const std::exception& e) {
        throw std::runtime_error("Ошибка в процессе верификации: " + std::string(e.what()));
    }
}