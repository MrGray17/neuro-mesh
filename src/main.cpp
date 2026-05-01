#include <iostream>
#include <csignal>
#include <memory>
#include "SovereignCell.hpp"
#include "AuditLogger.hpp"

// Global pointer for the signal handler to access the orchestrator
neuro_mesh::core::SovereignCell* g_cell_ptr = nullptr;

// Graceful shutdown handler
void handle_signal(int sig) {
    if (g_cell_ptr) {
        std::cout << "\n[MAIN] Signal " << sig << " received. Initiating graceful shutdown sequence...\n";
        g_cell_ptr->trigger_shutdown();
    }
}

int main() {
    // 1. Initialize the Asynchronous Data Diode (UDP Telemetry)
    neuro_mesh::telemetry::AuditLogger::initialize();

    // 2. Bind OS signals for clean exits
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::cout << "====================================================\n";
    std::cout << "  NEURO-MESH : SOVEREIGN AGENT INITIALIZING...      \n";
    std::cout << "====================================================\n";

    // 3. Instantiate the Sovereign Cell
    auto result = neuro_mesh::core::SovereignCell::create("SOVEREIGN_NODE_01");
    
    if (!result.error.empty()) {
        std::cerr << "[MAIN] FATAL BOOT ERROR: " << result.error << "\n";
        return 1;
    }

    // Transfer ownership to a local unique_ptr and set the raw pointer for the signal handler
    std::unique_ptr<neuro_mesh::core::SovereignCell> cell = std::move(result.cell);
    g_cell_ptr = cell.get();

    // 4. Enter the primary event loop (This blocks until trigger_shutdown is called)
    cell->run();

    // 5. Cleanup
    g_cell_ptr = nullptr;
    std::cout << "[MAIN] Neuro-Mesh Agent successfully detached. System offline.\n";
    
    return 0;
}
