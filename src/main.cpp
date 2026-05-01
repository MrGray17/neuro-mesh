#include "SovereignCell.hpp"
#include <iostream>
#include <csignal>
#include <memory>
#include <unistd.h>
#include <atomic>

std::unique_ptr<neuro_mesh::core::SovereignCell> global_cell = nullptr;
std::atomic<bool> g_shutdown_requested{false};
std::atomic<bool> g_vaccine_requested{false};

void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        g_shutdown_requested.store(true);
    } 
    else if (signum == SIGUSR1) {
        // STRICT POSIX COMPLIANCE: Never call functions in a signal handler.
        // Just flip an atomic flag so the main loop handles it safely.
        g_vaccine_requested.store(true);
    }
}

int main() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    std::signal(SIGUSR1, signal_handler); 

    std::string dynamic_node_id = "NODE_" + std::to_string(getpid());
    auto [cell, err] = neuro_mesh::core::SovereignCell::create(dynamic_node_id);
    
    if (!err.empty()) {
        std::cerr << "[MAIN] FATAL BOOT ERROR: " << err << std::endl;
        return 1;
    }

    global_cell = std::move(cell);
    
    // Pass the atomic flags into the safe main execution loop
    global_cell->run(&g_shutdown_requested, &g_vaccine_requested);

    return 0;
}
