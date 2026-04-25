// ⚙️ NEURO-MESH AGENT : VERSION ABSOLUTE SUPREME (PHASE 3 : MAILLAGE P2P)
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <process.h>
    #pragma comment(lib, "ws2_32.lib")
    #define CLOSE_SOCKET closesocket
    #define SLEEP_MS(x) Sleep(x)
    #define GET_PID _getpid
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/sysinfo.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <sys/mman.h> // 🛡️ Requis pour la mutation mémoire (Linux)
    #define CLOSE_SOCKET close
    #define SLEEP_MS(x) usleep((x) * 1000)
    #define GET_PID getpid
#endif

#include <iostream>
#include <cstring>
#include <string>
#include <cstdlib>
#include <ctime>
#include <limits.h>
#include <vector>
#include <thread>
#include <csignal>
#include <mutex> // 🛡️ CRUCIAL pour la gestion P2P multi-threads
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

// -----------------------------------------------------------------------------
// 🧠 MODULE 1 : OBFUSCATION (Décodeur Universel)
// -----------------------------------------------------------------------------
#define CRYPTO_KEY 0x42 

std::string neuro_decrypt(std::string cipher) {
    std::string output = cipher;
    for (size_t i = 0; i < cipher.size(); i++) {
        output[i] = cipher[i] ^ CRYPTO_KEY;
    }
    return output;
}

// -----------------------------------------------------------------------------
// 🧬 MODULE 2 : MUTATION DYNAMIQUE (Abstraction Élite)
// -----------------------------------------------------------------------------
#ifndef _WIN32
void __attribute__((aligned(4096))) secret_function() {
    int a = 10, b = 5;
    std::cout << "\033[1;30m[TEST LOGIQUE]\033[0m Résultat interne : " << (a + b) << std::endl;
}

void mutate_code() {
    size_t pagesize = sysconf(_SC_PAGESIZE);
    void* addr = (void*)((unsigned long)secret_function & ~(pagesize - 1));

    if (mprotect(addr, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect");
        return;
    }

    unsigned char* code_ptr = (unsigned char*)secret_function;
    for (int i = 0; i < 64; i++) {
        if (code_ptr[i] == 0x01 && code_ptr[i+1] == 0xd8) { 
            std::cout << "\033[1;33m[MUTATION]\033[0m Opcode ciblé trouvé. Réécriture de la RAM en cours...\n";
            code_ptr[i] = 0x29; 
            break;
        }
    }
    __builtin___clear_cache((char*)addr, (char*)addr + pagesize);
}
#else
void secret_function() {}
void mutate_code() {}
#endif

// -----------------------------------------------------------------------------
// 🕸️ MODULE 3 : DÉFENSE ACTIVE (Honeypot Tarpit)
// -----------------------------------------------------------------------------
void tarpit_honeypot() {
#ifdef _WIN32
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
#else
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
#endif

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(2222); 

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 10);
    std::cout << "\033[1;35m[MIRAGE]\033[0m Honeypot activé (Port 2222).\033[0m" << std::endl;

    while (true) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int addrlen = sizeof(client_addr);
        SOCKET client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
#else
        socklen_t addrlen = sizeof(client_addr);
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
#endif
        if (client_socket < 0) continue;

        char attacker_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, attacker_ip, INET_ADDRSTRLEN);

        std::cout << "\033[1;41;37m [!!! INTRUSION DÉTECTÉE SUR LE HONEYPOT !!!] \033[0m Cible: " << attacker_ip << std::endl;

        std::thread([client_socket]() {
            const char* banner = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n";
            send(client_socket, banner, strlen(banner), 0);
            while (true) {
                char poison[1024];
                for(int i = 0; i < 1024; i++) poison[i] = rand() % 256;
                if (send(client_socket, poison, 1024, 0) <= 0) break;
                SLEEP_MS(2000);
            }
            CLOSE_SOCKET(client_socket);
        }).detach();
    }
}

// -----------------------------------------------------------------------------
// 🌍 MODULE 4 : MAILLAGE P2P (Intelligence Collective)
// -----------------------------------------------------------------------------
struct Neighbor {
    std::string id;
    std::string ip;
    time_t last_seen;
};

std::vector<Neighbor> active_mesh;
std::mutex mesh_mutex; // Empêche les crashs quand plusieurs threads lisent/écrivent

// 🔊 BEACON : Crier sa présence sur le réseau
void send_mesh_beacon(std::string auto_id) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    char broadcast = '1';
#else
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int broadcast = 1;
#endif

    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    struct sockaddr_in broadcast_addr;
    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(9999); // Port dédié au P2P
    inet_pton(AF_INET, "255.255.255.255", &broadcast_addr.sin_addr);

    std::string beacon_msg = "NEURO_BEACON|" + auto_id;

    while (true) {
        sendto(sock, beacon_msg.c_str(), beacon_msg.length(), 0, (struct sockaddr*)&broadcast_addr, sizeof(broadcast_addr));
        SLEEP_MS(5000); // Pulse toutes les 5 secondes
    }
    CLOSE_SOCKET(sock);
}

// 👂 LISTENER : Écouter les autres agents
void listen_for_neighbors(std::string my_id) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in recv_addr;
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(9999);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    bind(sock, (struct sockaddr*)&recv_addr, sizeof(recv_addr));

    while (true) {
        char buffer[1024] = {0};
        struct sockaddr_in sender_addr;
#ifdef _WIN32
        int sender_len = sizeof(sender_addr);
#else
        socklen_t sender_len = sizeof(sender_addr);
#endif

        int bytes = recvfrom(sock, buffer, 1024, 0, (struct sockaddr*)&sender_addr, &sender_len);
        if (bytes > 0) {
            std::string msg(buffer, bytes);
            if (msg.find("NEURO_BEACON|") == 0) {
                std::string neighbor_id = msg.substr(13);
                
                // On s'ignore soi-même
                if (neighbor_id == my_id) continue;

                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sender_addr.sin_addr, ip_str, INET_ADDRSTRLEN);

                std::lock_guard<std::mutex> lock(mesh_mutex);
                bool found = false;
                for (auto& n : active_mesh) {
                    if (n.id == neighbor_id) {
                        n.last_seen = time(NULL);
                        found = true;
                        break;
                    }
                }
                
                if (!found) {
                    active_mesh.push_back({neighbor_id, ip_str, time(NULL)});
                    std::cout << "\033[1;32m[MAILLAGE P2P]\033[0m Nouveau voisin synchronisé : " << neighbor_id << " (" << ip_str << ")\033[0m\n";
                }
            }
        }
    }
    CLOSE_SOCKET(sock);
}


// -----------------------------------------------------------------------------
// 📡 GESTION RÉSEAU ET CRYPTOGRAPHIE (C2)
// -----------------------------------------------------------------------------
unsigned char AES_KEY[32];
unsigned char AES_IV[16];

std::string rsa_encrypt(EVP_PKEY* pub_key, const unsigned char* data, size_t data_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, data, data_len);
    unsigned char* out = new unsigned char[outlen];
    EVP_PKEY_encrypt(ctx, out, &outlen, data, data_len);
    std::string result((char*)out, outlen);
    delete[] out;
    EVP_PKEY_CTX_free(ctx);
    return result;
}

std::string encrypt_aes256(const std::string& plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char ciphertext[2048] = {0};
    int len = 0, ciphertext_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)plaintext.c_str(), plaintext.length());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)ciphertext, ciphertext_len);
}

std::string decrypt_aes256(const unsigned char* ciphertext, int ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char plaintext[2048] = {0};
    int len = 0, plaintext_len = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERREUR";
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext, plaintext_len);
}

std::string get_telemetry(const std::string& node_id) {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    long freeRAM = 0; int procs = 0;
#ifdef _WIN32
    MEMORYSTATUSEX statex; statex.dwLength = sizeof(statex); GlobalMemoryStatusEx(&statex);
    freeRAM = statex.ullAvailPhys / (1024 * 1024);
    SYSTEM_INFO sysinfo; GetSystemInfo(&sysinfo); procs = sysinfo.dwNumberOfProcessors;
#else
    struct sysinfo memInfo; sysinfo(&memInfo);
    freeRAM = (memInfo.freeram * memInfo.mem_unit) / (1024 * 1024); procs = memInfo.procs;
#endif
    return "{\"ID\":\"" + node_id + "\", \"HOST\":\"" + std::string(hostname) + "\", \"RAM_MB\":" + std::to_string(freeRAM) + ", \"PROCS\":" + std::to_string(procs) + "}";
}

// -----------------------------------------------------------------------------
// 🚀 BOUCLE PRINCIPALE
// -----------------------------------------------------------------------------
int main() {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

    // Mutation
    std::cout << "\033[1;36m[SYSTEME]\033[0m Initialisation de l'architecture polymorphique...\n";
    secret_function();
    mutate_code();
    secret_function();

    srand(time(NULL));

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    std::string auto_id = "NODE_" + std::to_string(GET_PID());
    
    std::string secret_msg("\x11\x16\x03\x0c\x06\x00\x1b", 7);
    std::cout << "\033[1;36m[SYSTEME]\033[0m Agent " << auto_id << " prêt. Statut initial : " << neuro_decrypt(secret_msg) << std::endl;

    // Lancement des systèmes de défense et de maillage en arrière-plan
    std::thread(tarpit_honeypot).detach();
    std::thread(send_mesh_beacon, auto_id).detach();
    std::thread(listen_for_neighbors, auto_id).detach();

    while (true) {
#ifdef _WIN32
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
#else
        int sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(8080);
        inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            CLOSE_SOCKET(sock); SLEEP_MS(3000); continue;
        }

        char pub_key_buffer[2048] = {0};
        int pk_len = recv(sock, pub_key_buffer, 2048, 0);
        if (pk_len <= 0) { CLOSE_SOCKET(sock); continue; }

        BIO* bio = BIO_new_mem_buf(pub_key_buffer, pk_len);
        EVP_PKEY* pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        RAND_bytes(AES_KEY, 32); RAND_bytes(AES_IV, 16);
        unsigned char session_material[48];
        memcpy(session_material, AES_KEY, 32); memcpy(session_material + 32, AES_IV, 16);

        std::string encrypted_session = rsa_encrypt(pub_key, session_material, 48);
        EVP_PKEY_free(pub_key);

        send(sock, encrypted_session.c_str(), encrypted_session.length(), 0);

        while (true) {
            std::string fresh_data = get_telemetry(auto_id);
            std::string encrypted_payload = encrypt_aes256(fresh_data);

            if (send(sock, encrypted_payload.c_str(), (int)encrypted_payload.length(), 0) < 0) break;

            char buffer[1024] = {0};
            int bytes_received = recv(sock, buffer, 1024, 0);
            if (bytes_received <= 0) break;

            std::string server_response = decrypt_aes256((unsigned char*)buffer, bytes_received);
            if (server_response == "ERREUR") continue;

            std::string cmd_part = server_response;
            std::string payload_part = "";
            size_t pipe_pos = server_response.find("|");

            if (pipe_pos != std::string::npos) {
                cmd_part = server_response.substr(0, pipe_pos);
                payload_part = server_response.substr(pipe_pos + 1);
            }

            if (cmd_part == "CMD:STANDBY") {
                std::cout << "\033[1;34m[FLUX]\033[0m Télémétrie OK | \033[1;32mSTANDBY\033[0m" << std::endl;
            }
            else if (cmd_part == "CMD:ISOLATE_NETWORK") {
                std::cout << "\033[1;41;37m [!!! AUTO-ISOLATION !!!] \033[0m" << std::endl;
            }

            SLEEP_MS(5000);
        }
        CLOSE_SOCKET(sock);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
