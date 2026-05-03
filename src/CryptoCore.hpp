// ============================================================
// NEURO-MESH : CRYPTOGRAPHIC IDENTITY CORE
// ============================================================
#pragma once
#include <string>
#include <memory>
#include <openssl/evp.h>

namespace neuro_mesh::crypto {

// RAII Wrapper for EVP_PKEY to prevent memory leaks
struct EVPKeyDeleter {
    void operator()(EVP_PKEY* key) const { EVP_PKEY_free(key); }
};
using UniquePKEY = std::unique_ptr<EVP_PKEY, EVPKeyDeleter>;

class IdentityCore {
public:
    static UniquePKEY generate_ed25519_key();
    
    // WHY: We strictly enforce Ed25519 contexts. Passing nullptr blindly in older OpenSSL 
    // versions causes undefined behavior or downgrade attacks.
    static std::string sign_payload(EVP_PKEY* priv_key, const std::string& data);
    static bool verify_signature(EVP_PKEY* pub_key, const std::string& data, const std::string& signature);
    
    static std::string get_pem_from_pubkey(EVP_PKEY* key);
    static UniquePKEY get_pubkey_from_pem(const std::string& pem);
};

} // namespace neuro_mesh::crypto
