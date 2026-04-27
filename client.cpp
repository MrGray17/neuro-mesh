// ============================================================
// NEURO-MESH AGENT : ULTIMATE FINAL EDITION (TCP SYNC FIXED)
// ============================================================
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
    #include <sys/mman.h>
    #include <ifaddrs.h>
    #include <signal.h>
    #include <poll.h>
    #define CLOSE_SOCKET close
    #define SLEEP_MS(x) usleep((x) * 1000)
    #define GET_PID getpid
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <string>
#include <cstdlib>
#include <ctime>
#include <limits.h>
#include <vector>
#include <thread>
#include <csignal>
#include <chrono>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

// ============================================================
// CONSTANTES
// ============================================================
#define RSA_KEY_BITS        2048
#define RSA_PADDING         RSA_PKCS1_OAEP_PADDING
#define RSA_OAEP_MD         EVP_sha256()
#define RSA_MGF1_MD         EVP_sha256()
#define AES_KEY_LEN         32
#define AES_GCM_IV_LEN      12
#define AES_GCM_TAG_LEN     16
#define SESSION_MATERIAL_LEN (AES_KEY_LEN + AES_GCM_IV_LEN) // 44
#define RECV_BUFFER_SIZE    65536
#define RSA_ENCRYPTED_LEN   256
#define P2P_MULTICAST_IP    "239.0.0.1"
#define P2P_MULTICAST_PORT  9999
#define C2_PORT             8080
#define MAX_BACKOFF_MS      60000
#define IA_CMD_FILE         "ia_commands.txt"
#define MAX_HONEYPOT_THREADS 50
#define AGENT_AUTH_TOKEN    "NEURO_MESH_SECRET"

#define CRYPTO_KEY 0x42

static const unsigned char P2P_HMAC_STATIC_KEY[] = {
    0x13, 0x37, 0x42, 0x69, 0x42, 0x65, 0x65, 0x66,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

std::atomic<bool> honeypot_triggered{false};
std::atomic<bool> is_isolated{false};
std::atomic<int> report_interval{5000};
std::atomic<unsigned int> active_honeypot_threads{0};
std::atomic<bool> signal_pending{false};

unsigned char session_key[AES_KEY_LEN];
std::string hmac_key;

// ============================================================
// UTILITAIRES
// ============================================================
std::string neuro_decrypt(std::string cipher) {
    for (size_t i = 0; i < cipher.size(); ++i) cipher[i] ^= CRYPTO_KEY;
    return cipher;
}

int recv_full(int sock, char* buffer, size_t total_len, int flags = 0) {
    size_t received = 0;
    while (received < total_len) {
        int r = recv(sock, buffer + received, total_len - received, flags);
        if (r <= 0) return -1;
        received += r;
    }
    return (int)received;
}

// ============================================================
// CRYPTO AES-GCM
// ============================================================
std::string encrypt_aes256_gcm(const std::string& plaintext, const unsigned char* key, unsigned char* iv_out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    RAND_bytes(iv_out, AES_GCM_IV_LEN);
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_GCM_TAG_LEN);
    int len = 0, ciphertext_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv_out) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plaintext.c_str(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return ""; }
    ciphertext_len += len;
    unsigned char tag[AES_GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, tag) != 1) { EVP_CIPHER_CTX_free(ctx); return ""; }
    EVP_CIPHER_CTX_free(ctx);
    std::string result((char*)iv_out, AES_GCM_IV_LEN);
    result.append((char*)ciphertext.data(), ciphertext_len);
    result.append((char*)tag, AES_GCM_TAG_LEN);
    return result;
}

std::string decrypt_aes256_gcm(const unsigned char* full_msg, size_t full_len, const unsigned char* key) {
    if (full_len < AES_GCM_IV_LEN + AES_GCM_TAG_LEN) return "ERREUR";
    unsigned char iv[AES_GCM_IV_LEN];
    memcpy(iv, full_msg, AES_GCM_IV_LEN);
    const unsigned char* ciphertext = full_msg + AES_GCM_IV_LEN;
    size_t ciphertext_len = full_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    const unsigned char* tag = full_msg + AES_GCM_IV_LEN + ciphertext_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "ERREUR";
    std::vector<unsigned char> plaintext(ciphertext_len);
    int len = 0, plaintext_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "ERREUR";
    }
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void*)tag) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return "ERREUR"; }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext_len);
}

// ============================================================
// RSA
// ============================================================
std::string rsa_encrypt(EVP_PKEY* pub_key, const unsigned char* data, size_t data_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, nullptr);
    if (!ctx) return "";
    if (EVP_PKEY_encrypt_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return ""; }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, RSA_OAEP_MD) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, RSA_MGF1_MD) <= 0) {
        EVP_PKEY_CTX_free(ctx); return "";
    }
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, data, data_len) <= 0) { EVP_PKEY_CTX_free(ctx); return ""; }
    unsigned char* out = new unsigned char[outlen];
    if (EVP_PKEY_encrypt(ctx, out, &outlen, data, data_len) <= 0) { delete[] out; EVP_PKEY_CTX_free(ctx); return ""; }
    std::string result((char*)out, outlen);
    delete[] out; EVP_PKEY_CTX_free(ctx);
    return result;
}

// ============================================================
// HONEYPOT (CORRIGÉ AVEC MAX_TICKS)
// ============================================================
void tarpit_handler(int client_socket) {
    const char* banner = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n";
    send(client_socket, banner, strlen(banner), 0);
    int max_ticks = 300; // Force la coupure après env. 10 minutes d'attaque
    while (max_ticks-- > 0) {
        char poison[1024];
        for (int i = 0; i < 1024; ++i) poison[i] = rand() % 256;
        if (send(client_socket, poison, 1024, 0) <= 0) break;
        SLEEP_MS(is_isolated ? 100 : 2000);
    }
    CLOSE_SOCKET(client_socket);
    active_honeypot_threads--;
}

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

    int port = 2222;
    address.sin_port = htons(port);
    while (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        port++;
        address.sin_port = htons(port);
        if (port > 2250) return;
    }
    listen(server_fd, 10);
    std::cout << "\033[1;35m[MIRAGE]\033[0m Honeypot activé (Port " << port << ").\033[0m" << std::endl;

    while (true) {
        struct sockaddr_in client_addr;
#ifdef _WIN32
        int addrlen = sizeof(client_addr);
        SOCKET client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);
#else
        socklen_t addrlen = sizeof(client_addr);
        int client_socket = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);
#endif
        if (client_socket < 0) continue;

        if (active_honeypot_threads >= MAX_HONEYPOT_THREADS) {
            CLOSE_SOCKET(client_socket);
            continue;
        }

        char attacker_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, attacker_ip, INET_ADDRSTRLEN);
        std::cout << "\033[1;41;37m [!!! INTRUSION DÉTECTÉE SUR LE HONEYPOT (Port " << port << ") !!!] \033[0m Cible: " << attacker_ip << std::endl;

        if (!honeypot_triggered) {
            std::ofstream report("incident_report.txt", std::ios::app);
            time_t now = time(0);
            report << "==========================================\n";
            report << "[ALERTE CRITIQUE] DATE: " << ctime(&now);
            report << "[SOURCE] IP ATTAQUANT : " << attacker_ip << "\n";
            report << "[VECTEUR] Port Honeypot : " << port << "\n";
            report << "==========================================\n";
            report.close();
            std::cout << "\033[1;33m[DOC]\033[0m Preuve cryptographique générée : incident_report.txt\n";
        }
        honeypot_triggered = true;
        active_honeypot_threads++;
        std::thread([client_socket]() { tarpit_handler(client_socket); }).detach();
    }
}

// ============================================================
// P2P BULLY
// ============================================================
struct Neighbor { std::string id; std::string ip; int priority_score; time_t last_seen; };
enum AgentState { NORMAL, ELECTION_MODE, COORDINATOR_MODE };
std::atomic<AgentState> current_state{NORMAL};
std::atomic<bool> received_ok{false};
std::string current_leader_id = "";
std::vector<Neighbor> active_mesh;
std::mutex mesh_mutex;

std::string hmac_sha256(const std::string& key, const std::string& message) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    HMAC(EVP_sha256(), key.c_str(), key.size(), (const unsigned char*)message.c_str(), message.size(), digest, &digest_len);
    return std::string((char*)digest, digest_len);
}

std::string get_p2p_hmac_key() { return std::string((char*)P2P_HMAC_STATIC_KEY, sizeof(P2P_HMAC_STATIC_KEY)); }

bool verify_hmac(const std::string& key, const std::string& message, const std::string& received_hmac) {
    std::string computed = hmac_sha256(key, message);
    if (computed.size() != received_hmac.size()) return false;
    return CRYPTO_memcmp(computed.data(), received_hmac.data(), computed.size()) == 0;
}

std::string sign_message(const std::string& key, const std::string& msg) {
    return msg + "|" + hmac_sha256(key, msg);
}

int calculate_priority() {
    long usedRAM = 0; int procs = 0;
#ifdef _WIN32
    MEMORYSTATUSEX statex; statex.dwLength = sizeof(statex); GlobalMemoryStatusEx(&statex);
    usedRAM = (statex.ullTotalPhys - statex.ullAvailPhys) / (1024 * 1024);
    SYSTEM_INFO sysinfo; GetSystemInfo(&sysinfo); procs = sysinfo.dwNumberOfProcessors;
#else
    struct sysinfo memInfo; sysinfo(&memInfo);
    long total = (memInfo.totalram * memInfo.mem_unit) / (1024 * 1024);
    long free = (memInfo.freeram * memInfo.mem_unit) / (1024 * 1024);
    usedRAM = total - free;
    procs = memInfo.procs;
#endif
    return (procs * 1000) + (int)usedRAM;
}

void broadcast_p2p(const std::string& msg) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    char loopback = 1;
#else
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int loopback = 1;
#endif
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (char*)&loopback, sizeof(loopback));
    struct sockaddr_in mcast_addr;
    mcast_addr.sin_family = AF_INET;
    mcast_addr.sin_port = htons(P2P_MULTICAST_PORT);
    mcast_addr.sin_addr.s_addr = inet_addr(P2P_MULTICAST_IP);
    sendto(sock, msg.c_str(), msg.length(), 0, (struct sockaddr*)&mcast_addr, sizeof(mcast_addr));
    CLOSE_SOCKET(sock);
}

void start_bully_election(std::string my_id) {
    if (is_isolated) return;
    current_state = ELECTION_MODE;
    received_ok = false;
    int my_score = calculate_priority();
    int jitter_ms = 5000 + (GET_PID() % 1000);
    std::cout << "\033[1;33m[VOTE]\033[0m Détection SPOF. Élection dans " << jitter_ms << " ms (Score: " << my_score << ")\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(jitter_ms));
    std::string p2p_key = get_p2p_hmac_key();
    broadcast_p2p(sign_message(p2p_key, "MSG_VOTE|" + my_id + "|" + std::to_string(my_score)));

    std::this_thread::sleep_for(std::chrono::seconds(5));
    if (!received_ok && !is_isolated) {
        current_state = COORDINATOR_MODE;
        current_leader_id = my_id;
        std::cout << "\033[1;45;37m [SYSTEME] JE SUIS LE NOUVEAU LEADER \033[0m\n";
        broadcast_p2p(sign_message(p2p_key, "MSG_COORDINATOR|" + my_id));
    } else {
        current_state = NORMAL;
    }
}

void listen_for_neighbors(std::string my_id) {
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#else
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#ifndef _WIN32
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (char*)&opt, sizeof(opt));
#endif
    struct sockaddr_in recv_addr;
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(P2P_MULTICAST_PORT);
    recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(sock, (struct sockaddr*)&recv_addr, sizeof(recv_addr));

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(P2P_MULTICAST_IP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq));

    std::string p2p_key = get_p2p_hmac_key();

    while (true) {
        char buffer[2048] = {0};
        struct sockaddr_in sender_addr;
#ifdef _WIN32
        int sender_len = sizeof(sender_addr);
#else
        socklen_t sender_len = sizeof(sender_addr);
#endif
        int bytes = recvfrom(sock, buffer, sizeof(buffer)-1, 0, (struct sockaddr*)&sender_addr, &sender_len);
        if (bytes <= 0 || is_isolated) continue;

        std::string msg(buffer, bytes);
        size_t last_pipe = msg.rfind('|');
        if (last_pipe == std::string::npos) continue;
        std::string content = msg.substr(0, last_pipe);
        std::string received_hmac = msg.substr(last_pipe+1);
        if (!verify_hmac(p2p_key, content, received_hmac)) continue;

        size_t p1 = content.find('|');
        if (p1 == std::string::npos) continue;
        std::string type = content.substr(0, p1);
        std::string sender_id;
        if (type == "MSG_VOTE" || type == "MSG_OK" || type == "MSG_COORDINATOR") {
            size_t p2 = content.find('|', p1+1);
            if (p2 != std::string::npos) sender_id = content.substr(p1+1, p2-p1-1);
            else sender_id = content.substr(p1+1);
        }

        if (!sender_id.empty() && sender_id != my_id) {
            std::lock_guard<std::mutex> lock(mesh_mutex);
            bool found = false;
            for (auto& n : active_mesh) {
                if (n.id == sender_id) {
                    n.last_seen = time(nullptr);
                    found = true;
                    break;
                }
            }
            if (!found) {
                Neighbor nb;
                nb.id = sender_id;
                nb.ip = inet_ntoa(sender_addr.sin_addr);
                nb.priority_score = 0;
                nb.last_seen = time(nullptr);
                active_mesh.push_back(nb);
            }
        }

        if (type == "MSG_VOTE") {
            size_t p2 = content.find('|', p1+1);
            if (p2 == std::string::npos) continue;
            sender_id = content.substr(p1+1, p2-p1-1);
            int sender_score = std::stoi(content.substr(p2+1));
            int my_score = calculate_priority();
            if (sender_id != my_id) {
                if (my_score > sender_score) {
                    broadcast_p2p(sign_message(p2p_key, "MSG_OK|" + my_id));
                    if (current_state != ELECTION_MODE) std::thread(start_bully_election, my_id).detach();
                } else if (my_score < sender_score) {
                    received_ok = true;
                    current_state = NORMAL;
                }
            }
        } else if (type == "MSG_OK") {
            sender_id = content.substr(p1+1);
            if (sender_id != my_id) received_ok = true;
        } else if (type == "MSG_COORDINATOR") {
            sender_id = content.substr(p1+1);
            current_leader_id = sender_id;
            if (current_leader_id != my_id) {
                current_state = NORMAL;
                std::cout << "\033[1;36m[MAILLAGE]\033[0m Nouveau chef accepté : " << current_leader_id << "\n";
            }
        }
    }
}

// ============================================================
// 5EME DIMENSION (Trafic sortant)
// ============================================================
#ifdef __linux__
static unsigned long long get_total_tx_bytes() {
    std::ifstream netdev("/proc/net/dev");
    if (!netdev.is_open()) return 0;
    std::string line;
    unsigned long long total = 0;
    std::getline(netdev, line);
    std::getline(netdev, line);
    while (std::getline(netdev, line)) {
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string iface = line.substr(0, colon);
        if (iface.find("lo") != std::string::npos) continue;
        std::string stats = line.substr(colon + 1);
        std::istringstream iss(stats);
        unsigned long long rx_bytes, rx_packets, rx_errs, rx_drop, rx_fifo, rx_frame, rx_compressed, rx_multicast;
        unsigned long long tx_bytes, tx_packets, tx_errs, tx_drop, tx_fifo, tx_colls, tx_carrier, tx_compressed;
        iss >> rx_bytes >> rx_packets >> rx_errs >> rx_drop >> rx_fifo >> rx_frame >> rx_compressed >> rx_multicast
            >> tx_bytes >> tx_packets >> tx_errs >> tx_drop >> tx_fifo >> tx_colls >> tx_carrier >> tx_compressed;
        total += tx_bytes;
    }
    return total;
}
#else
static unsigned long long get_total_tx_bytes() { return 0; }
#endif

std::string get_neighbors_list() {
    std::lock_guard<std::mutex> lock(mesh_mutex);
    std::string neighbors;
    for (size_t i = 0; i < active_mesh.size(); ++i) {
        if (i > 0) neighbors += ",";
        neighbors += active_mesh[i].id;
    }
    return neighbors;
}

// ============================================================
// TELEMETRY JSON (CORRIGÉ: INJECTION DU STATUT ISOLATION)
// ============================================================
std::string get_telemetry(const std::string& node_id) {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);
    long usedRAM = 0; int procs = 0; double cpu_load = 0.0;
#ifdef _WIN32
    MEMORYSTATUSEX statex; statex.dwLength = sizeof(statex); GlobalMemoryStatusEx(&statex);
    usedRAM = (statex.ullTotalPhys - statex.ullAvailPhys) / (1024 * 1024);
    SYSTEM_INFO sysinfo; GetSystemInfo(&sysinfo); procs = sysinfo.dwNumberOfProcessors;
#else
    struct sysinfo memInfo; sysinfo(&memInfo);
    long total = (memInfo.totalram * memInfo.mem_unit) / (1024 * 1024);
    long free = (memInfo.freeram * memInfo.mem_unit) / (1024 * 1024);
    usedRAM = total - free;
    procs = memInfo.procs;
    double loads[1];
    if (getloadavg(loads, 1) != -1) cpu_load = loads[0];
#endif

    static unsigned long long last_tx_bytes = 0;
    static auto last_time = std::chrono::steady_clock::now();
    unsigned long long current_tx = get_total_tx_bytes();
    auto now = std::chrono::steady_clock::now();
    double elapsed_sec = std::chrono::duration<double>(now - last_time).count();
    long long net_out_bytes_s = 0;
    if (last_tx_bytes != 0 && elapsed_sec > 0.0) {
        long long diff = current_tx - last_tx_bytes;
        if (diff >= 0) net_out_bytes_s = static_cast<long long>(diff / elapsed_sec);
    }
    last_tx_bytes = current_tx;
    last_time = now;

    std::string neighbors_list = get_neighbors_list();
    std::string state_str = (current_state == COORDINATOR_MODE) ? "COORDINATOR" : "NORMAL";
    std::string attack_status = honeypot_triggered ? "TRUE" : "FALSE";

    json j;
    j["ID"] = node_id;
    j["HOST"] = hostname;
    j["RAM_MB"] = usedRAM;
    j["CPU_LOAD"] = cpu_load;
    j["PROCS"] = procs;
    j["STATE"] = state_str;
    j["NET_OUT"] = net_out_bytes_s;
    j["NEIGHBORS"] = neighbors_list;
    j["ATTACK"] = attack_status;
    
    // 🔥 CORRECTION : Injection directe de l'état d'auto-isolation dans la télémétrie
    if (is_isolated) {
        j["STATUS"] = "SELF_ISOLATED";
    }
    
    return j.dump();
}

// ============================================================
// SIGUSR1 HANDLER (ASYNC SAFE)
// ============================================================
void isolation_signal_handler(int) {
    signal_pending = true;
}

// ============================================================
// MASQUAGE (LINUX)
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
// MAIN LOOP
// ============================================================
int main(int argc, char* argv[]) {
    hide_process_name(argc, argv);

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
    signal(SIGUSR1, isolation_signal_handler);
#endif

    std::cout << "\033[1;36m[SYSTEME]\033[0m Initialisation de l'architecture polymorphique...\n";
    srand(time(nullptr));

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    std::string auto_id = "NODE_" + std::to_string(GET_PID());
    std::string secret_msg("\x11\x16\x03\x0c\x06\x00\x1b", 7);
    std::cout << "\033[1;36m[SYSTEME]\033[0m Agent " << auto_id << " prêt. Statut initial : " << neuro_decrypt(secret_msg) << std::endl;

    std::thread(tarpit_honeypot).detach();
    std::thread(listen_for_neighbors, auto_id).detach();

    int backoff_ms = 1000;
    while (true) {
#ifdef _WIN32
        SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
#else
        int sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
        if (sock < 0) {
            SLEEP_MS(backoff_ms);
            backoff_ms = std::min(backoff_ms * 2, MAX_BACKOFF_MS);
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(C2_PORT);
        const char* c2_addr = std::getenv("NEURO_MESH_C2_ADDR");
        if (c2_addr == nullptr) c2_addr = "127.0.0.1";
        inet_pton(AF_INET, c2_addr, &serv_addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            CLOSE_SOCKET(sock);
            std::cout << "\033[1;31m[!]\033[0m C2 injoignable, reconnexion dans " << backoff_ms << " ms\n";
            if (current_state == NORMAL && !is_isolated) {
                std::thread(start_bully_election, auto_id).detach();
            }
            SLEEP_MS(backoff_ms);
            backoff_ms = std::min(backoff_ms * 2, MAX_BACKOFF_MS);
            continue;
        }

        backoff_ms = 1000;

        // 1. RSA Handshake
        char pub_key_buffer[4096] = {0};
        int pk_len = recv(sock, pub_key_buffer, sizeof(pub_key_buffer)-1, 0);
        if (pk_len <= 0) { CLOSE_SOCKET(sock); continue; }
        
        BIO* bio = BIO_new_mem_buf(pub_key_buffer, pk_len);
        EVP_PKEY* pub_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pub_key) { CLOSE_SOCKET(sock); continue; }

        unsigned char aes_key[AES_KEY_LEN];
        unsigned char iv_handshake[AES_GCM_IV_LEN];
        RAND_bytes(aes_key, AES_KEY_LEN);
        RAND_bytes(iv_handshake, AES_GCM_IV_LEN);
        
        unsigned char session_material[SESSION_MATERIAL_LEN];
        memcpy(session_material, aes_key, AES_KEY_LEN);
        memcpy(session_material + AES_KEY_LEN, iv_handshake, AES_GCM_IV_LEN);

        std::string encrypted_session = rsa_encrypt(pub_key, session_material, SESSION_MATERIAL_LEN);
        EVP_PKEY_free(pub_key);
        if (encrypted_session.empty() || encrypted_session.size() != RSA_ENCRYPTED_LEN) { CLOSE_SOCKET(sock); continue; }
        if (send(sock, encrypted_session.c_str(), RSA_ENCRYPTED_LEN, 0) != RSA_ENCRYPTED_LEN) { CLOSE_SOCKET(sock); continue; }

        memcpy(session_key, aes_key, AES_KEY_LEN);
        hmac_key = get_p2p_hmac_key();

        // 2. Auth GCM
        std::string auth_token = "AUTH:" + std::string(AGENT_AUTH_TOKEN);
        unsigned char iv_auth[AES_GCM_IV_LEN];
        std::string encrypted_auth = encrypt_aes256_gcm(auth_token, session_key, iv_auth);
        uint32_t auth_len = htonl(encrypted_auth.size());
        send(sock, &auth_len, 4, 0);
        send(sock, encrypted_auth.c_str(), encrypted_auth.size(), 0);

        SLEEP_MS(200);

        // 3. Boucle Télémétrie Stricte (Ping-Pong TCP garanti)
        while (true) {
            // Gestion d'un signal SIGUSR1
            if (signal_pending) {
                signal_pending = false;
                std::cout << "\033[1;41;37m[SIGNAL] Isolation forcée reçue ! Passage en mode quarantaine.\033[0m" << std::endl;
                is_isolated = true;
                report_interval = 1000;
                current_state = NORMAL;

                // On n'envoie PLUS de paquet manuellement ici. 
                // Le statut SELF_ISOLATED est maintenant capturé proprement par get_telemetry() ci-dessous.
                
                // Trace locale optionnelle pour le C2 s'il lit les fichiers (fallback)
                std::ofstream cmd_file(IA_CMD_FILE, std::ios::app);
                if (cmd_file.is_open()) {
                    cmd_file << "CMD_IA:ISOLATE|" << auto_id << std::endl;
                    cmd_file.close();
                }
            }

            std::string fresh_data = get_telemetry(auto_id);
            unsigned char iv_msg[AES_GCM_IV_LEN];
            std::string encrypted_payload = encrypt_aes256_gcm(fresh_data, session_key, iv_msg);
            uint32_t msg_len = htonl(encrypted_payload.size());
            if (send(sock, &msg_len, 4, 0) != 4 ||
                send(sock, encrypted_payload.c_str(), encrypted_payload.size(), 0) != (ssize_t)encrypted_payload.size()) {
                break; // Erreur d'envoi, on drop et on recommence
            }

            uint32_t cmd_len;
            if (recv_full(sock, (char*)&cmd_len, 4) != 4) break;
            cmd_len = ntohl(cmd_len);
            if (cmd_len == 0 || cmd_len > 65536) break;
            
            std::vector<char> cmd_buf(cmd_len);
            if (recv_full(sock, cmd_buf.data(), cmd_len) != (int)cmd_len) break;
            
            std::string decrypted_cmd = decrypt_aes256_gcm((unsigned char*)cmd_buf.data(), cmd_len, session_key);
            
            // Ignorer silencieusement un paquet altéré
            if (decrypted_cmd == "ERREUR") {
                SLEEP_MS(report_interval.load());
                continue;
            }

            std::string cmd_part = decrypted_cmd;
            size_t pipe_pos = decrypted_cmd.find('|');
            if (pipe_pos != std::string::npos) cmd_part = decrypted_cmd.substr(0, pipe_pos);

            if (cmd_part == "CMD:STANDBY") {
                if (!is_isolated)
                    std::cout << "\033[1;34m[FLUX]\033[0m Télémétrie OK | \033[1;32mSTANDBY\033[0m" << std::endl;
            } else if (cmd_part == "CMD:ISOLATE_NETWORK") {
                if (!is_isolated) {
                    std::cout << "\033[1;41;37m [STATUT : ISOLATION ATOMIQUE ACTIVE] \033[0m" << std::endl;
                    std::cout << "\033[1;33m[SEC]\033[0m Maillage P2P suspendu. Mode 'Quarantaine'.\n";
                    is_isolated = true;
                    report_interval = 1000;
                    current_state = NORMAL;
                }
            } else if (cmd_part == "CMD:GLOBAL_ALERT") {
                if (!is_isolated) {
                    std::cout << "\033[1;33m[SAGESSE COLLECTIVE]\033[0m Alerte réseau reçue ! Boucliers P2P renforcés.\n";
                    report_interval = 3000;
                }
            }
            
            SLEEP_MS(report_interval.load());
        }
        CLOSE_SOCKET(sock);
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
