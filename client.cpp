// ⚙️ NEURO-MESH AGENT : VERSION SAGESSE COLLECTIVE
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
    #define CLOSE_SOCKET close
    #define SLEEP_MS(x) usleep((x) * 1000)
    #define GET_PID getpid
#endif

#include <iostream>
#include <cstring>
#include <string>
#include <cstdlib>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

unsigned char AES_KEY[32];
unsigned char AES_IV[16];

void daemonize() {
#ifdef _WIN32
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);
#else
    pid_t pid = fork();
    if (pid < 0) exit(EXIT_FAILURE); 
    if (pid > 0) exit(EXIT_SUCCESS); 
    if (setsid() < 0) exit(EXIT_FAILURE); 
    pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);
    if (pid > 0) exit(EXIT_SUCCESS);
    chdir("/"); 
    int fd = open("/dev/null", O_RDWR);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
#endif
}

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
    long freeRAM = 0;
    int procs = 0;
#ifdef _WIN32
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    freeRAM = statex.ullAvailPhys / (1024 * 1024);
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    procs = sysinfo.dwNumberOfProcessors;
#else
    struct sysinfo memInfo;
    sysinfo(&memInfo);
    freeRAM = (memInfo.freeram * memInfo.mem_unit) / (1024 * 1024);
    procs = memInfo.procs;
#endif
    return "{\"ID\":\"" + node_id + "\", \"HOST\":\"" + std::string(hostname) + "\", \"RAM_MB\":" + std::to_string(freeRAM) + ", \"PROCS\":" + std::to_string(procs) + "}";
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    // Pour nos tests locaux avec 3 terminaux, je désactive le daemonize 
    // pour que tu puisses voir les affichages du client dans ton terminal.
    // daemonize(); 

    std::string auto_id = "NODE_" + std::to_string(GET_PID());
    std::cout << "\033[1;36m[SYSTEME]\033[0m Initialisation de l'Agent " << auto_id << "..." << std::endl;

    while (true) {
#ifdef _WIN32
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
#else
        int sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(8080);
        inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr); // Re-configuré pour ton ThinkPad local

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            CLOSE_SOCKET(sock);
            SLEEP_MS(3000); 
            continue; 
        }

        char pub_key_buffer[2048] = {0};
        int pk_len = recv(sock, pub_key_buffer, 2048, 0);
        if (pk_len <= 0) { CLOSE_SOCKET(sock); continue; }

        BIO* bio = BIO_new_mem_buf(pub_key_buffer, pk_len);
        EVP_PKEY* pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
        BIO_free(bio);

        RAND_bytes(AES_KEY, 32);
        RAND_bytes(AES_IV, 16);

        unsigned char session_material[48];
        memcpy(session_material, AES_KEY, 32);
        memcpy(session_material + 32, AES_IV, 16);

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

            std::string server_command = decrypt_aes256((unsigned char*)buffer, bytes_received);

            // 🧠 INTELLIGENCE ET RÉPONSES AUX ORDRES
            if (server_command == "CMD:STANDBY") {
                std::cout << "\033[1;34m[FLUX]\033[0m Télémétrie OK | \033[1;32mSTANDBY\033[0m" << std::endl;
            } 
            else if (server_command == "CMD:ISOLATE_NETWORK") {
                std::cout << "\033[1;41;37m [!!! AUTO-ISOLATION : NOEUD COMPROMIS !!!] \033[0m" << std::endl;
            }
            else if (server_command.find("CMD:STRENGTHEN_DEFENSE") != std::string::npos) {
                std::string threat_host = server_command.substr(server_command.find("|") + 1);
                std::cout << "\033[1;45;37m [SAGESSE COLLECTIVE] Alerte critique reçue du Cerveau ! \033[0m" << std::endl;
                std::cout << "\033[1;35m  -> La machine [" << threat_host << "] est compromise. Renforcement des boucliers.\033[0m" << std::endl;
            }
            
            SLEEP_MS(5000); // Latence normale de 5 secondes
        }
        CLOSE_SOCKET(sock);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
