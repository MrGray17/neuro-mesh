#include "SystemJailer.hpp"
#include "AuditLogger.hpp"
#include <csignal>
#include <iostream>

namespace neuro_mesh::core {

void SystemJailer::imprison(pid_t pid) {
    std::lock_guard<std::mutex> lock(m_jail_mutex);
    
    // Cryogenically freeze the process
    if (kill(pid, SIGSTOP) == 0) {
        m_jailed_pids.push_back(pid);
        telemetry::AuditLogger::emit_json(
            telemetry::AuditLevel::INFO, "SystemJailer", "SIGSTOP_APPLIED", 
            "PID: " + std::to_string(pid), "Process cryogenically frozen."
        );
    }
}

void SystemJailer::release_all() {
    std::lock_guard<std::mutex> lock(m_jail_mutex);
    
    for (pid_t pid : m_jailed_pids) {
        // FIX: Change SIGCONT to SIGKILL (Signal 9). 
        // We must completely destroy the threat, not release it.
        if (kill(pid, SIGKILL) == 0) {
            telemetry::AuditLogger::emit_json(
                telemetry::AuditLevel::INFO, "SystemJailer", "SIGKILL_APPLIED", 
                "PID: " + std::to_string(pid), "Threat completely eradicated from OS memory."
            );
        }
    }
    m_jailed_pids.clear(); // Empty the jail
}

} // namespace neuro_mesh::core
