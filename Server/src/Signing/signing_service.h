#pragma once

#include <string>
#include <stdexcept>

#include "../Rsa/rsa_crypto.h" 

class SigningServiceError : public std::runtime_error {
public:
    explicit SigningServiceError(const std::string& message) : std::runtime_error(message) {}
};

class SigningService {
public:
   
    SigningService(const std::string& private_key_path, 
                   const std::string& public_key_n_path, 
                   const std::string& public_key_e_path);

    std::string signHash(const std::string& hex_hash) const;

    
    std::string getPublicKeyN_Hex() const;

    
    std::string getPublicKeyE_Hex() const;

private:
    
    void loadKeys();

    BigInt d_key; 
    BigInt n_key; 
    BigInt e_key; 
    bool keys_are_loaded = false;
};