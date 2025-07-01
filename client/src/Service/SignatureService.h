#pragma once
#include <string>
#include "../Rsa/rsa_crypto.h" 
class SignatureService {
public:
    std::string hash_file(const std::string& file_path) const;
    void save_signature(const std::string& original_file_path, const std::string& signature_hex) const;
    bool verify_signature(
        const std::string& original_file_path,
        const std::string& signature_file_path,
        const BigInt& public_n, 
        const BigInt& public_e
    ) const;
};