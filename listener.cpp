// ⚙️ NEURO-MESH C2 : VERSION ULTIMATE SUPREME (ZÉRO ERREUR)
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <thread>
#include <ctime>
#include <chrono>
#include <map>
#include <mutex>
#include <vector>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

// 🧬 STRUCTURE DE L'AGENT
struct AgentNode {
    std::string id = "PENDING";
    std::string hostname = "UNKNOWN";
    std::string ip = "0.0.0.0";
    long ram_mb = 0;
    int procs = 0;
    long latency = 0;
    std::string status = "HANDSHAKE";
    unsigned char session_key[32];
    unsigned char session_iv[16];
};

std::map<int, AgentNode> active_nodes;
std::vector<std::string> security_logs;
std::mutex system_mutex;
EVP_PKEY *server_rsa_key = nullptr;

// 🌐 EXPORTATION VERS L'API JSON
void export_to_json_unsafe() {
    std::ofstream file("api.json");
    if (!file.is_open()) return;

    file << "{\n";
    file << "  \"architecture\": \"NEURO-MESH (Sovereign Distributed C2)\",\n";
    file << "  \"system_status\": \"ONLINE\",\n";
    file << "  \"active_nodes\": [\n";

    bool first = true;
    for (auto const& [sock, node] : active_nodes) {
        if (!first) file << ",\n";
        file << "    { \"id\": \"" << node.id
             << "\", \"hostname\": \"" << node.hostname
             << "\", \"ip\": \"" << node.ip
             << "\", \"ram_mb\": " << node.ram_mb
             << ", \"procs\": " << node.procs
             << ", \"latency\": " << node.latency
             << ", \"status\": \"" << node.status << "\" }";
        first = false;
    }

    file << "\n  ],\n";
    file << "  \"logs\": [\n";

    // Correction Ultime du Warning : Utilisation stricte de size_t
    size_t start = (security_logs.size() > 10) ? security_logs.size() - 10 : 0;
    bool first_log = true;
    for (size_t i = start; i < security_logs.size(); i++) {
        if (!first_log) file << ",\n";
        std::string safe_log = security_logs[i];
        size_t pos;
        while ((pos = safe_log.find("\"")) != std::string::npos) safe_log.replace(pos, 1, "'");

        file << "    \"" << safe_log << "\"";
        first_log = false;
    }

    file << "\n  ]\n";
    file << "}\n";
    file.close();
}

// 📝 JOURNALISATION SILENCIEUSE
void log_event_unsafe(const std::string& message) {
    time_t now = time(0); struct tm tstruct; char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "[%H:%M:%S]", &tstruct);
    security_logs.push_back(std::string(buf) + " " + message);

    std::cout << "\033[1;30m" << buf << " " << message << "\033[0m" << std::endl;
    export_to_json_unsafe();
}

// 🔐 MOTEUR CRYPTOGRAPHIQUE
std::string rsa_decrypt(EVP_PKEY* priv_key, const unsigned char* encrypted_data, size_t data_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    EVP_PKEY_decrypt_init(ctx); 
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    size_t outlen; 
    EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_data, data_len);
    unsigned char* out = new unsigned char[outlen];
    if (EVP_PKEY_decrypt(ctx, out, &outlen, encrypted_data, data_len) <= 0) { 
        delete[] out; 
        EVP_PKEY_CTX_free(ctx); 
        return ""; 
    }
    std::string result((char*)out, outlen); 
    delete[] out; 
    EVP_PKEY_CTX_free(ctx); 
    return result;
}

EVP_PKEY* generate_rsa_key() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL); 
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048); 
    EVP_PKEY *pkey = NULL; 
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx); 
    return pkey;
}

std::string get_public_key_pem(EVP_PKEY* pkey) {
    BIO *bio = BIO_new(BIO_s_mem()); 
    PEM_write_bio_PUBKEY(bio, pkey);
    char *data; 
    long len = BIO_get_mem_data(bio, &data); 
    std::string result(data, len);
    BIO_free(bio); 
    return result;
}

std::string decrypt_aes256(const unsigned char* ciphertext, int ciphertext_len, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
    unsigned char plaintext[2048] = {0}; 
    int len = 0, plaintext_len = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv); 
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

std::string encrypt_aes256(const std::string& plaintext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
    unsigned char ciphertext[2048] = {0}; 
    int len = 0, ciphertext_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv); 
    EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)plaintext.c_str(), plaintext.length()); 
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len); 
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx); 
    return std::string((char*)ciphertext, ciphertext_len);
}

// 🕸️ DÉCOUVERTE DU MAILLAGE (NEIGHBOR DISCOVERY)
std::string get_neighbor_list(int requester_sock) {
    std::string list = "NEIGHBORS:";
    for (auto const& [sock, node] : active_nodes) {
        if (sock != requester_sock && node.status != "HANDSHAKE") {
            list += node.ip + ",";
        }
    }
    return list;
}

void broadcast_alert_unsafe(int compromised_socket, const std::string& threat_host) {
    log_event_unsafe("[SAGESSE COLLECTIVE] Propagation de l'alerte réseau : " + threat_host);
    for (auto const& [sock, node] : active_nodes) {
        if (sock != compromised_socket && node.status != "HANDSHAKE") {
            std::string alert_msg = "CMD:STRENGTHEN_DEFENSE|" + threat_host;
            std::string encrypted_cmd = encrypt_aes256(alert_msg, node.session_key, node.session_iv);
            send(sock, encrypted_cmd.c_str(), encrypted_cmd.length(), 0);
        }
    }
}

// 📡 GESTION DES NEURONES (AGENTS)
void handle_client(int client_socket, struct sockaddr_in client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

    AgentNode this_node;
    this_node.ip = std::string(client_ip);

    {
        std::lock_guard<std::mutex> lock(system_mutex);
        active_nodes[client_socket] = this_node;
        log_event_unsafe("[ACCÈS] Connexion TCP : " + std::string(client_ip));
    }

    std::string pub_key_pem = get_public_key_pem(server_rsa_key);
    send(client_socket, pub_key_pem.c_str(), pub_key_pem.length(), 0);

    unsigned char rsa_buffer[1024] = {0};
    int rsa_bytes = recv(client_socket, rsa_buffer, sizeof(rsa_buffer), 0);

    if (rsa_bytes < 256) { 
        std::lock_guard<std::mutex> lock(system_mutex); 
        active_nodes.erase(client_socket); 
        close(client_socket); 
        return; 
    }

    std::string decrypted_session = rsa_decrypt(server_rsa_key, rsa_buffer, rsa_bytes);
    if (decrypted_session.length() < 48) {
        std::lock_guard<std::mutex> lock(system_mutex);
        active_nodes.erase(client_socket);
        log_event_unsafe("[INTRUSION] Handshake invalide depuis " + std::string(client_ip));
        close(client_socket); 
        return;
    }

    memcpy(this_node.session_key, decrypted_session.c_str(), 32); 
    memcpy(this_node.session_iv, decrypted_session.c_str() + 32, 16);
    this_node.status = "STABLE"; 
    this_node.latency = 5000;

    {
        std::lock_guard<std::mutex> lock(system_mutex);
        active_nodes[client_socket] = this_node;
        log_event_unsafe("[SOUVERAINETÉ] Tunnel AES sécurisé avec " + std::string(client_ip));
    }

    bool is_first_message = true; 
    auto last_msg_time = std::chrono::steady_clock::now();
    unsigned char buffer[2048];

    while (true) {
        memset(buffer, 0, 2048);
        int bytes_received = recv(client_socket, buffer, 2048, 0);

        if (bytes_received <= 0) {
            std::lock_guard<std::mutex> lock(system_mutex);
            log_event_unsafe("[ALERTE] Liaison rompue : " + active_nodes[client_socket].hostname);
            active_nodes.erase(client_socket);
            export_to_json_unsafe();
            break;
        }

        std::string decrypted = decrypt_aes256(buffer, bytes_received, this_node.session_key, this_node.session_iv);
        if (decrypted == "ERREUR") continue;

        try {
            size_t id_pos = decrypted.find("\"ID\":\""); 
            if (id_pos != std::string::npos) this_node.id = decrypted.substr(id_pos + 6, decrypted.find("\"", id_pos + 6) - (id_pos + 6));
            
            size_t host_pos = decrypted.find("\"HOST\":\""); 
            if (host_pos != std::string::npos) this_node.hostname = decrypted.substr(host_pos + 8, decrypted.find("\"", host_pos + 8) - (host_pos + 8));
            
            size_t ram_pos = decrypted.find("\"RAM_MB\":"); 
            if (ram_pos != std::string::npos) this_node.ram_mb = std::stol(decrypted.substr(ram_pos + 9, decrypted.find(",", ram_pos) - (ram_pos + 9)));
            
            size_t procs_pos = decrypted.find("\"PROCS\":"); 
            if (procs_pos != std::string::npos) this_node.procs = std::stoi(decrypted.substr(procs_pos + 8, decrypted.find("}", procs_pos) - (procs_pos + 8)));
        } catch (...) {}

        auto current_time = std::chrono::steady_clock::now();
        long diff = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - last_msg_time).count();
        last_msg_time = current_time;

        if (is_first_message) { diff = 5000; is_first_message = false; }
        this_node.latency = diff; 
        std::string command_to_send;

        {
            std::lock_guard<std::mutex> lock(system_mutex);
            if (diff < 800) {
                this_node.status = "COMPROMIS";
                log_event_unsafe("[ANOMALIE] Flood détecté sur " + this_node.hostname);
                command_to_send = "CMD:ISOLATE_NETWORK";
                active_nodes[client_socket] = this_node;
                broadcast_alert_unsafe(client_socket, this_node.hostname);
            } else {
                this_node.status = "STABLE";
                // Le Cerveau envoie l'ordre ET la liste des voisins !
                command_to_send = "CMD:STANDBY|" + get_neighbor_list(client_socket);
                active_nodes[client_socket] = this_node;
            }
            export_to_json_unsafe();
        }

        std::string encrypted_cmd = encrypt_aes256(command_to_send, this_node.session_key, this_node.session_iv);
        send(client_socket, encrypted_cmd.c_str(), encrypted_cmd.length(), 0);
    }
    close(client_socket);
}

int main() {
    int server_fd; 
    struct sockaddr_in address; 
    int opt = 1;
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(8080);
    
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 50);

    server_rsa_key = generate_rsa_key();

    {
        std::lock_guard<std::mutex> lock(system_mutex);
        log_event_unsafe("Moteur Cryptographique Initialisé : RSA-2048 prêt.");
        log_event_unsafe("C2 Backend en route sur le port 8080. API JSON activée.");
    }

    while (true) {
        struct sockaddr_in client_addr; 
        socklen_t client_len = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (new_socket >= 0) {
            std::thread(handle_client, new_socket, client_addr).detach();
        }
    }
    return 0;
}
