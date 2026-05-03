// ============================================================
// NEURO-MESH : UNIFIED EDGE ENTRYPOINT (V6.1 ROBUST)
// ============================================================
#include "SovereignCell.hpp"
#include <iostream>
#include <memory>
#include <thread>
#include <atomic>
#include <csignal>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <cstring>

// Global coordination flags
std::unique_ptr<neuro_mesh::core::SovereignCell> global_cell = nullptr;
std::atomic<bool> g_shutdown_requested{false};
std::atomic<bool> g_vaccine_requested{false};

void signal_handler(int) { 
    g_shutdown_requested.store(true); 
}

/**
 * Listens for local management commands from the Python C2 server.
 * Uses PID-unique socket paths to support multiple agents on one host.
 */
void secure_ipc_listener() {
    // 🔥 THE FIX: Create a unique socket path based on the current Process ID
    std::string socket_path = "/tmp/neuro_mesh_" + std::to_string(getpid()) + ".sock";
    
    int server_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (server_fd < 0) return;

    // Clean up any stale socket file[cite: 1]
    unlink(socket_path.c_str());

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[IPC] Bind failed for " << socket_path << std::endl;
        close(server_fd); 
        return;
    }
    
    // Set permissions so the Python C2 (even if non-root) can communicate[cite: 1]
    chmod(socket_path.c_str(), 0666); 
    listen(server_fd, 5);

    struct pollfd pfd;
    pfd.fd = server_fd;
    pfd.events = POLLIN;

    while (!g_shutdown_requested.load()) {
        // Poll with 100ms timeout to keep the thread responsive to shutdown[cite: 1]
        if (poll(&pfd, 1, 100) > 0 && (pfd.revents & POLLIN)) {
            int client_fd = accept(server_fd, nullptr, nullptr);
            if (client_fd < 0) continue;

            // KERNEL-LEVEL AUTHENTICATION:[cite: 1]
            // Verify that the sender is either Root (UID 0) or the user who started this agent.
            struct ucred credentials;
            socklen_t ucred_length = sizeof(struct ucred);
            if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &ucred_length) == 0) {
                if (credentials.uid == 0 || credentials.uid == getuid()) {
                    char buffer[128] = {0};
                    if (recv(client_fd, buffer, sizeof(buffer) - 1, 0) > 0) {
                        // Handle re-integration and vaccination[cite: 1]
                        if (strstr(buffer, "CMD:VACCINATE") || strstr(buffer, "CMD:REJOIN")) {
                            std::cout << "\033[1;32m[IPC]\033[0m Signal de guérison reçu.\n";
                            g_vaccine_requested.store(true);
                        } 
                        // Command acknowledgment for the C2 logs
                        else if (strstr(buffer, "CMD:ISOLATE")) {
                            std::cout << "\033[1;31m[IPC]\033[0m Signal d'isolation C2 confirmé.\n";
                        }
                    }
                }
            }
            close(client_fd);
        }
    }

    close(server_fd);
    unlink(socket_path.c_str());
}

int main() {
    // 1. Resource Hardening[cite: 1]
    struct rlimit rl;
    rl.rlim_cur = 65535;
    rl.rlim_max = 65535;
    setrlimit(RLIMIT_NOFILE, &rl);

    // 2. Setup POSIX Signals[cite: 1]
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGPIPE, SIG_IGN); 

    // 3. Sovereign Core Initialization[cite: 1]
    std::string dynamic_node_id = "NODE_" + std::to_string(getpid());
    auto result = neuro_mesh::core::SovereignCell::create(dynamic_node_id);
    
    if (!result.error.empty() || !result.cell) {
        std::cerr << "[FATAL] Neuro-Mesh Boot Failure: " << result.error << std::endl;
        return 1;
    }
    global_cell = std::move(result.cell);
    
    // 4. Launch Secure Management Thread[cite: 1]
    std::thread ipc_thread(secure_ipc_listener);

    std::cout << "\033[1;36m[SYSTEM]\033[0m Sovereign Edge Agent Active (" << dynamic_node_id << ")\n";
    
    // 5. Enter Primary Domain Loop[cite: 1]
    global_cell->run(&g_shutdown_requested, &g_vaccine_requested);
    
    // 6. Graceful Decommissioning[cite: 1]
    g_shutdown_requested.store(true);
    if (ipc_thread.joinable()) ipc_thread.join();
    
    std::cout << "[SYSTEM] Kernel links cleaned. Agent offline." << std::endl;
    return 0;
}
