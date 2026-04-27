// ============================================================
// NEURO-MESH C2 : ULTIMATE CORRECTED EDITION (NO DEADLOCK)
// ============================================================
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <thread>
#include <csignal>
#include <ctime>
#include <chrono>
#include <map>
#include <set>
#include <mutex>
#include <atomic>
#include <deque>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <algorithm>
#include <fcntl.h>
#include <sys/file.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void send_telegram_alert(const std::string& message);
void log_event_safe(const std::string& message);
void log_event_unsafe(const std::string& message);

#define RSA_KEY_BITS        2048
#define RSA_PADDING         RSA_PKCS1_OAEP_PADDING
#define RSA_OAEP_MD         EVP_sha256()
#define RSA_MGF1_MD         EVP_sha256()
#define AES_KEY_LEN         32
#define AES_GCM_IV_LEN      12
#define AES_GCM_TAG_LEN     16
#define SESSION_MATERIAL_LEN (AES_KEY_LEN + AES_GCM_IV_LEN)
#define RECV_BUFFER_SIZE    65536
#define RSA_ENCRYPTED_LEN   256
#define MAX_LOG_ENTRIES     1000
#define IA_CMD_FILE         "ia_commands.txt"
#define JSON_TMP_FILE       "api_tmp.json"
#define JSON_FILE           "api.json"
#define WS_PORT             8081
#define AGENT_AUTH_TOKEN    "NEURO_MESH_SECRET"
#define MAX_C2_CONNECTIONS  500

struct AgentNode {
    std::string id = "PENDING";
    std::string hostname = "UNKNOWN";
    std::string ip = "0.0.0.0";
    std::string neighbors = "";
    long ram_mb = 0;
    double cpu_load = 0.0;
    int procs = 0;
    long latency = 0;
    long net_out = 0;
    std::string status = "HANDSHAKE";
    std::string p2p_state = "NORMAL";
    unsigned char session_key[AES_KEY_LEN];
};

std::map<int, AgentNode> active_nodes;
std::deque<std::string> security_logs;
std::mutex system_mutex;
std::mutex log_mutex;
EVP_PKEY *server_rsa_key = nullptr;
std::atomic<unsigned int> active_c2_connections{0};

// WebSocket
std::set<int> ws_clients;
std::mutex ws_mutex;

// ============================================================
// WEBSOCKET HELPERS (sans deadlock)
// ============================================================
std::string base64_encode(const unsigned char* input, int length) {
    static const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int i = 0;
    unsigned char char_array_3[3], char_array_4[4];
    while (length--) {
        char_array_3[i++] = *(input++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for (i = 0; i < 4; i++) result += b64[char_array_4[i]];
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        for (int j = 0; j < i + 1; j++) result += b64[char_array_4[j]];
        while (i++ < 3) result += '=';
    }
    return result;
}

std::string websocket_accept_key(const std::string& key) {
    std::string magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = key + magic;
    unsigned char sha[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)combined.c_str(), combined.size(), sha);
    return base64_encode(sha, SHA_DIGEST_LENGTH);
}

void ws_send(int fd, const std::string& message) {
    std::vector<unsigned char> frame;
    frame.push_back(0x81);
    size_t len = message.size();
    if (len <= 125) {
        frame.push_back(0x80 | len);
    } else if (len <= 65535) {
        frame.push_back(0x80 | 126);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    } else {
        frame.push_back(0x80 | 127);
        for (int i = 7; i >= 0; i--) frame.push_back((len >> (i * 8)) & 0xFF);
    }
    frame.insert(frame.end(), message.begin(), message.end());

    ssize_t sent = send(fd, (char*)frame.data(), frame.size(), MSG_NOSIGNAL);
    if (sent <= 0) {
        close(fd);
        // Ne pas toucher à ws_clients ici – on va utiliser un cleanup périodique
    }
}

void cleanup_dead_websockets() {
    std::lock_guard<std::mutex> lock(ws_mutex);
    for (auto it = ws_clients.begin(); it != ws_clients.end(); ) {
        int fd = *it;
        char buf;
        ssize_t r = recv(fd, &buf, 1, MSG_DONTWAIT | MSG_PEEK);
        if (r == 0 || (r == -1 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            close(fd);
            it = ws_clients.erase(it);
        } else {
            ++it;
        }
    }
}

void broadcast_websocket(const std::string& json_content) {
    // On ne diffuse qu'aux clients encore valides (sans deadlock)
    std::lock_guard<std::mutex> lock(ws_mutex);
    for (int fd : ws_clients) {
        ws_send(fd, json_content);
    }
}

void websocket_server_thread() {
    int ws_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ws_fd < 0) return;
    int opt = 1;
    setsockopt(ws_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(ws_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(WS_PORT);
    if (bind(ws_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Erreur bind WebSocket port " << WS_PORT << std::endl;
        close(ws_fd);
        return;
    }
    listen(ws_fd, 10);
    log_event_safe("[WEBSOCKET] Serveur WebSocket actif sur le port " + std::to_string(WS_PORT));

    // Timer pour nettoyer les connexions mortes
    auto last_cleanup = std::chrono::steady_clock::now();

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(ws_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) continue;

        // Nettoyage périodique des dead sockets
        auto now = std::chrono::steady_clock::now();
        if (now - last_cleanup > std::chrono::seconds(5)) {
            cleanup_dead_websockets();
            last_cleanup = now;
        }

        char buffer[4096] = {0};
        recv(client_fd, buffer, sizeof(buffer)-1, 0);
        std::string request(buffer);
        // Vérification du token dans l'URL (ex: GET /?token=NEURO_MESH_SECRET)
        if (request.find("token=" + std::string(AGENT_AUTH_TOKEN)) == std::string::npos) {
            close(client_fd);
            continue;
        }
        size_t key_pos = request.find("Sec-WebSocket-Key: ");
        if (key_pos != std::string::npos) {
            size_t end = request.find("\r\n", key_pos);
            std::string key = request.substr(key_pos + 19, end - (key_pos + 19));
            std::string accept = websocket_accept_key(key);
            std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                                   "Upgrade: websocket\r\n"
                                   "Connection: Upgrade\r\n"
                                   "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
            send(client_fd, response.c_str(), response.size(), 0);
            {
                std::lock_guard<std::mutex> lock(ws_mutex);
                ws_clients.insert(client_fd);
            }
            // Envoyer l'état courant
            std::ifstream json_file(JSON_FILE);
            if (json_file.is_open()) {
                std::string content((std::istreambuf_iterator<char>(json_file)),
                                    std::istreambuf_iterator<char>());
                json_file.close();
                ws_send(client_fd, content);
            }
        } else {
            close(client_fd);
        }
    }
    close(ws_fd);
}

// ============================================================
// UTILITAIRES
// ============================================================
int recv_full(int sock, char* buffer, size_t total_len, int flags = 0) {
    size_t received = 0;
    while (received < total_len) {
        ssize_t r = recv(sock, buffer + received, total_len - received, flags);
        if (r <= 0) return -1;
        received += r;
    }
    return static_cast<int>(received);
}

void add_log_unsafe(const std::string& message) {
    if (security_logs.size() >= MAX_LOG_ENTRIES) {
        security_logs.pop_front();
    }
    security_logs.push_back(message);
}

void log_event_safe(const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex);
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "[%H:%M:%S]", &tstruct);
    std::string full_msg = std::string(buf) + " " + message;
    add_log_unsafe(full_msg);
    std::cout << "\033[1;30m" << full_msg << "\033[0m" << std::endl;
}

void log_event_unsafe(const std::string& message) {
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "[%H:%M:%S]", &tstruct);
    std::string full_msg = std::string(buf) + " " + message;
    add_log_unsafe(full_msg);
    std::cout << "\033[1;30m" << full_msg << "\033[0m" << std::endl;
}

// Version sans verrouillage (appelée uniquement quand system_mutex est déjà pris)
void export_to_json_unsafe() {
    std::vector<std::pair<int, AgentNode>> snapshot;
    for (const auto& p : active_nodes) {
        snapshot.push_back(p);
    }
    json j;
    j["architecture"] = "NEURO-MESH (Sovereign Distributed C2)";
    j["system_status"] = "ONLINE";
    j["active_nodes"] = json::array();
    for (const auto& p : snapshot) {
        const auto& node = p.second;
        json node_json;
        node_json["id"] = node.id;
        node_json["hostname"] = node.hostname;
        node_json["ip"] = node.ip;
        node_json["ram_mb"] = node.ram_mb;
        node_json["cpu_load"] = node.cpu_load;
        node_json["procs"] = node.procs;
        node_json["latency"] = node.latency;
        node_json["net_out_bytes_s"] = node.net_out;
        node_json["neighbors"] = node.neighbors;
        node_json["status"] = node.status;
        node_json["p2p_state"] = node.p2p_state;
        j["active_nodes"].push_back(node_json);
    }
    j["logs"] = json::array();
    size_t start = (security_logs.size() > 15) ? security_logs.size() - 15 : 0;
    for (size_t i = start; i < security_logs.size(); ++i) {
        j["logs"].push_back(security_logs[i]);
    }
    std::ofstream file(JSON_TMP_FILE);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Impossible d'ouvrir " << JSON_TMP_FILE << std::endl;
        return;
    }
    file << j.dump(4);
    file.close();
    if (std::rename(JSON_TMP_FILE, JSON_FILE) != 0) {
        std::cerr << "[ERROR] rename failed" << std::endl;
    } else {
        std::cout << "[DEBUG] api.json mis à jour" << std::endl;
    }
    broadcast_websocket(j.dump());
}

// ============================================================
// CRYPTOGRAPHIE
// ============================================================
std::string rsa_decrypt(EVP_PKEY* priv_key, const unsigned char* encrypted_data, size_t data_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    if (!ctx) return "";
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, RSA_OAEP_MD) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, RSA_MGF1_MD) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, encrypted_data, data_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    unsigned char* out = new unsigned char[outlen];
    if (EVP_PKEY_decrypt(ctx, out, &outlen, encrypted_data, data_len) <= 0) {
        delete[] out;
        EVP_PKEY_CTX_free(ctx);
        return "";
    }
    std::string result(reinterpret_cast<char*>(out), outlen);
    delete[] out;
    EVP_PKEY_CTX_free(ctx);
    return result;
}

EVP_PKEY* generate_rsa_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) return nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

std::string get_public_key_pem(EVP_PKEY* pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return "";
    if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
        BIO_free(bio);
        return "";
    }
    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    BIO_free(bio);
    return result;
}

// AES-GCM
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
        EVP_CIPHER_CTX_free(ctx);
        return "ERREUR";
    }
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERREUR";
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "ERREUR";
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext_len);
}

// Correction : taille exacte de la chaîne (15)
std::string derive_hmac_key(const unsigned char* aes_key, size_t aes_key_len) {
    unsigned char digest[32];
    unsigned int len;
    const char* salt = "P2P_HMAC_DERIVE";
    HMAC(EVP_sha256(), aes_key, aes_key_len,
         (const unsigned char*)salt, strlen(salt), digest, &len);
    return std::string(reinterpret_cast<char*>(digest), 32);
}

// ============================================================
// RÉSEAU ET COMMUNICATION
// ============================================================
// Version appelée uniquement quand system_mutex est déjà verrouillé
std::string get_neighbor_list_unsafe(int requester_sock) {
    std::string list = "NEIGHBORS:";
    for (auto const& [sock, node] : active_nodes) {
        if (sock != requester_sock && node.status != "HANDSHAKE")
            list += node.ip + ",";
    }
    return list;
}

void broadcast_alert_unsafe(int compromised_socket, const std::string& threat_host) {
    log_event_unsafe("[SAGESSE COLLECTIVE] Propagation de l'alerte réseau. Cible initiale : " + threat_host);
    for (auto const& [sock, node] : active_nodes) {
        if (sock != compromised_socket && node.status == "STABLE") {
            std::string alert_msg = "CMD:GLOBAL_ALERT|" + threat_host;
            unsigned char iv[AES_GCM_IV_LEN];
            std::string encrypted = encrypt_aes256_gcm(alert_msg, node.session_key, iv);
            uint32_t out_len = htonl(encrypted.size());
            // Envoi du préfixe de longueur puis du message
            if (send(sock, &out_len, 4, 0) != 4) {
                log_event_unsafe("[ERREUR] Échec envoi longueur alerte à sock " + std::to_string(sock));
                continue;
            }
            if (send(sock, encrypted.c_str(), encrypted.size(), 0) != (ssize_t)encrypted.size()) {
                log_event_unsafe("[ERREUR] Échec envoi alerte à sock " + std::to_string(sock));
            }
        }
    }
}

// ============================================================
// IA COMMANDS
// ============================================================
void check_ia_commands() {
    while (true) {
        int fd = open(IA_CMD_FILE, O_RDWR | O_CREAT, 0666);
        if (fd != -1) {
            if (flock(fd, LOCK_EX) == 0) {
                std::string content;
                char buf[1024];
                ssize_t n;
                while ((n = read(fd, buf, sizeof(buf))) > 0) {
                    content.append(buf, n);
                }
                std::istringstream iss(content);
                std::string line;
                while (std::getline(iss, line)) {
                    if (line.find("CMD_IA:ISOLATE|") != std::string::npos) {
                        std::string target_id = line.substr(15);
                        std::lock_guard<std::mutex> lock(system_mutex);
                        for (auto& [sock, node] : active_nodes) {
                            if (node.id == target_id && node.status != "COMPROMIS") {
                                node.status = "COMPROMIS";
                                log_event_unsafe("\033[1;45;37m[CORTEX IA]\033[0m Isolement HEURISTIQUE ordonné pour : " + target_id);
                                broadcast_alert_unsafe(sock, node.hostname);
                                std::string telegram_msg = "🧠 [CORTEX IA] Anomalie interceptée ! Isolation : " + target_id + " (" + node.hostname + ")";
                                std::thread(send_telegram_alert, telegram_msg).detach();
                                export_to_json_unsafe();
                            }
                        }
                    }
                }
                if (ftruncate(fd, 0) == -1) { /* ignorer */ }
                flock(fd, LOCK_UN);
            }
            close(fd);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// ============================================================
// GESTION D'UN CLIENT (AGENT)
// ============================================================
void handle_client(int client_socket, struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    AgentNode this_node;
    this_node.ip = std::string(client_ip);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Envoyer la clé publique RSA
    std::string pub_key_pem = get_public_key_pem(server_rsa_key);
    if (send(client_socket, pub_key_pem.c_str(), pub_key_pem.length(), 0) < 0) {
        close(client_socket);
        return;
    }

    // Recevoir la session AES chiffrée (256 octets)
    unsigned char rsa_buffer[RSA_ENCRYPTED_LEN];
    int total_received = 0;
    while (total_received < RSA_ENCRYPTED_LEN) {
        int bytes = recv(client_socket, rsa_buffer + total_received, RSA_ENCRYPTED_LEN - total_received, 0);
        if (bytes <= 0) {
            close(client_socket);
            return;
        }
        total_received += bytes;
    }

    std::string decrypted_session = rsa_decrypt(server_rsa_key, rsa_buffer, RSA_ENCRYPTED_LEN);
    if (decrypted_session.size() < SESSION_MATERIAL_LEN) {
        close(client_socket);
        return;
    }
    memcpy(this_node.session_key, decrypted_session.c_str(), AES_KEY_LEN);
    this_node.status = "STABLE";
    this_node.latency = 5000;

    // ========== AUTHENTIFICATION AGENT (réactivée) ==========
    uint32_t auth_len;
    if (recv_full(client_socket, (char*)&auth_len, 4) != 4) {
        close(client_socket);
        return;
    }
    auth_len = ntohl(auth_len);
    if (auth_len == 0 || auth_len > 4096) {
        close(client_socket);
        return;
    }
    std::vector<char> auth_buf(auth_len);
    if (recv_full(client_socket, auth_buf.data(), auth_len) != (int)auth_len) {
        close(client_socket);
        return;
    }
    std::string decrypted_auth = decrypt_aes256_gcm((unsigned char*)auth_buf.data(), auth_len, this_node.session_key);
    if (decrypted_auth != "AUTH:" + std::string(AGENT_AUTH_TOKEN)) {
        close(client_socket);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(system_mutex);
        active_nodes[client_socket] = this_node;
        log_event_unsafe("[ACCÈS] Connexion TCP authentifiée : " + std::string(client_ip));
        log_event_unsafe("[SOUVERAINETÉ] Tunnel AES-GCM établi avec " + std::string(client_ip));
        export_to_json_unsafe();
    }

    bool is_first_message = true;
    auto last_msg_time = std::chrono::steady_clock::now();

    while (true) {
        uint32_t msg_len;
        if (recv_full(client_socket, (char*)&msg_len, 4) != 4) break;
        msg_len = ntohl(msg_len);
        if (msg_len == 0 || msg_len > 65536) break;
        std::vector<char> enc_buf(msg_len);
        if (recv_full(client_socket, enc_buf.data(), msg_len) != (int)msg_len) break;
        std::string decrypted = decrypt_aes256_gcm((unsigned char*)enc_buf.data(), msg_len, this_node.session_key);
        if (decrypted == "ERREUR") continue;

        try {
            json j = json::parse(decrypted);
            if (j.contains("ID")) this_node.id = j["ID"];
            if (j.contains("HOST")) this_node.hostname = j["HOST"];
            if (j.contains("RAM_MB")) this_node.ram_mb = j["RAM_MB"];
            if (j.contains("CPU_LOAD")) this_node.cpu_load = j["CPU_LOAD"];
            if (j.contains("PROCS")) this_node.procs = j["PROCS"];
            if (j.contains("NET_OUT")) this_node.net_out = j["NET_OUT"];
            if (j.contains("NEIGHBORS")) this_node.neighbors = j["NEIGHBORS"];
            if (j.contains("ATTACK") && j["ATTACK"] == "TRUE") this_node.status = "COMPROMIS";
            if (j.contains("STATUS") && j["STATUS"] == "SELF_ISOLATED") {
                this_node.status = "COMPROMIS";
                log_event_unsafe("\033[1;41;37m[SELF-ISOLATION]\033[0m Agent " + this_node.id + " s'est auto-isolé.");
            }
            if (j.contains("STATE")) {
                std::string state = j["STATE"];
                if (state == "COORDINATOR" && this_node.p2p_state != "COORDINATOR") {
                    this_node.p2p_state = "COORDINATOR";
                    std::lock_guard<std::mutex> lock(system_mutex);
                    log_event_unsafe("\033[1;36m[RÉSILIENCE]\033[0m L'agent " + this_node.id + " a maintenu le maillage !");
                } else {
                    this_node.p2p_state = state;
                }
            }
        } catch (const std::exception& e) {
            continue;
        }

        auto current_time = std::chrono::steady_clock::now();
        long diff = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - last_msg_time).count();
        last_msg_time = current_time;
        if (is_first_message) { diff = 5000; is_first_message = false; }
        this_node.latency = diff;

        std::string command_to_send;
        {
            std::lock_guard<std::mutex> lock(system_mutex);
            // Synchronisation de l'état depuis la map globale
            auto it = active_nodes.find(client_socket);
            if (it != active_nodes.end() && it->second.status == "COMPROMIS") {
                this_node.status = "COMPROMIS";
            }
            if (this_node.status == "COMPROMIS" || diff < 400) {
                bool was_stable = (active_nodes[client_socket].status != "COMPROMIS");
                this_node.status = "COMPROMIS";
                command_to_send = "CMD:ISOLATE_NETWORK";
                active_nodes[client_socket] = this_node;
                if (was_stable) {
                    log_event_unsafe("\033[1;41;37m[INTRUSION]\033[0m Menace critique confirmée sur " + this_node.hostname);
                    broadcast_alert_unsafe(client_socket, this_node.hostname);
                    std::string telegram_msg = "🚨 [HONEYPOT] Intrusion détectée sur l'agent : " + this_node.id + " (" + this_node.hostname + "). Isolation P2P en cours.";
                    std::thread(send_telegram_alert, telegram_msg).detach();
                }
            } else {
                this_node.status = "STABLE";
                // Utilisation de la version _unsafe car le mutex est déjà pris
                command_to_send = "CMD:STANDBY|" + get_neighbor_list_unsafe(client_socket);
                active_nodes[client_socket] = this_node;
            }
            export_to_json_unsafe();
        }

        unsigned char iv_out[AES_GCM_IV_LEN];
        std::string encrypted_cmd = encrypt_aes256_gcm(command_to_send, this_node.session_key, iv_out);
        uint32_t out_len = htonl(encrypted_cmd.size());
        if (send(client_socket, &out_len, 4, 0) != 4) break;
        if (send(client_socket, encrypted_cmd.c_str(), encrypted_cmd.size(), 0) != (ssize_t)encrypted_cmd.size()) break;
    }
    close(client_socket);
    {
        std::lock_guard<std::mutex> lock(system_mutex);
        active_nodes.erase(client_socket);
        export_to_json_unsafe();
    }
}

// ============================================================
// TELEGRAM
// ============================================================
std::string get_telegram_token() {
    const char* token = std::getenv("NEURO_MESH_TELEGRAM_TOKEN");
    return token ? std::string(token) : "";
}
std::string get_telegram_chat_id() {
    const char* chat_id = std::getenv("NEURO_MESH_TELEGRAM_CHAT_ID");
    return chat_id ? std::string(chat_id) : "";
}

void send_telegram_alert(const std::string& message) {
    std::string token = get_telegram_token();
    std::string chat_id = get_telegram_chat_id();
    if (token.empty() || chat_id.empty()) return;

    CURL *curl = curl_easy_init();
    if (!curl) return;
    char *encoded_msg = curl_easy_escape(curl, message.c_str(), message.length());
    if (!encoded_msg) {
        curl_easy_cleanup(curl);
        return;
    }
    std::string url = "https://api.telegram.org/bot" + token + "/sendMessage?chat_id=" + chat_id + "&text=" + encoded_msg;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_perform(curl);
    curl_free(encoded_msg);
    curl_easy_cleanup(curl);
}

// ============================================================
// MASQUAGE DU PROCESSUS
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
    hide_process_name(argc, argv);

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Erreur création socket\n";
        return 1;
    }
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Erreur bind\n";
        return 1;
    }
    if (listen(server_fd, 50) < 0) {
        std::cerr << "Erreur listen\n";
        return 1;
    }

    server_rsa_key = generate_rsa_key();
    if (!server_rsa_key) {
        std::cerr << "Erreur génération clé RSA\n";
        return 1;
    }

    log_event_safe("Moteur Cryptographique Initialisé : RSA-2048 OAEP prêt.");
    log_event_safe("C2 Backend en route sur le port 8080. Intelligence Collective Activée.");
    log_event_safe("Liaison Command Center Mobile : Opérationnelle.");

    std::thread(check_ia_commands).detach();
    std::thread(websocket_server_thread).detach();

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (new_socket >= 0) {
            if (active_c2_connections < MAX_C2_CONNECTIONS) {
                active_c2_connections++;
                std::thread([fd = new_socket, addr = client_addr]() {
                    handle_client(fd, addr);
                    active_c2_connections--;
                }).detach();
            } else {
                close(new_socket);
                log_event_safe("[C2] Connexion refusée : limite de threads atteinte (" + std::to_string(MAX_C2_CONNECTIONS) + ")");
            }
        }
    }

    close(server_fd);
    EVP_PKEY_free(server_rsa_key);
    return 0;
}
