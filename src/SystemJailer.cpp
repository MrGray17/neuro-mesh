// ============================================================
// NEURO-MESH : SYSTEM JAILER (FAIL-SECURE EDITION)
// ============================================================
#include "SystemJailer.hpp"
#include "AuditLogger.hpp"
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h> 
#include <system_error>

namespace neuro_mesh::defense {

SystemJailer::SystemJailer() {
    m_jail_path = "/sys/fs/cgroup/neuro_jail";
    if (!initialize_base_cgroup()) {
         telemetry::AuditLogger::emit_json(
            telemetry::AuditLevel::WARNING, "SystemJailer", "DEGRADED_MODE", 
            "KERNEL", "cgroup v2 unavailable or permission denied. Falling back to POSIX signals."
        );
    }
}

SystemJailer::~SystemJailer() {
    // Note: A true sovereign agent leaves no trace, but removing the cgroup 
    // requires ensuring no processes are left inside. We leave it persistent for now.
}

bool SystemJailer::initialize_base_cgroup() {
    std::error_code ec;
    
    // Explicit error handling: check if directory exists or can be created
    if (!std::filesystem::exists(m_jail_path, ec)) {
        if (!std::filesystem::create_directory(m_jail_path, ec)) {
            return false;
        }
    }
    
    // Attempt to enforce CPU limits (0.01% CPU)
    std::ofstream cpu_max(m_jail_path / "cpu.max");
    if (!cpu_max.is_open()) return false;
    
    cpu_max << "100 1000000";
    if (cpu_max.fail()) return false;
    cpu_max.close();
    
    return true;
}

bool SystemJailer::imprison(uint32_t pid) {
    // 0. Pre-flight check: Verify process exists and we have permissions
    if (kill(pid, 0) != 0) return false; 

    bool contained = false;
    std::error_code ec;

    // 1. PRIMARY CONTAINMENT: cgroup v2 Resource Throttling
    if (std::filesystem::exists(m_jail_path / "cgroup.procs", ec)) {
        std::ofstream procs_file(m_jail_path / "cgroup.procs");
        if (procs_file.is_open()) {
            procs_file << pid;
            if (!procs_file.fail()) {
                contained = true;
                telemetry::AuditLogger::emit_json(
                    telemetry::AuditLevel::DEFENSE_ACTION, "SystemJailer", "CGROUP_JAIL", 
                    "PID: " + std::to_string(pid), "Resource throttled to 0.01% CPU."
                );
            }
            procs_file.close();
        }
    }

    // 2. SECONDARY CONTAINMENT: POSIX SIGSTOP (Cryogenic Freeze)
    // If cgroup fails (e.g., WSL2, missing root, or cgroup v1), we freeze the process.
    if (!contained) {
        if (kill(pid, SIGSTOP) == 0) {
            contained = true;
            telemetry::AuditLogger::emit_json(
                telemetry::AuditLevel::DEFENSE_ACTION, "SystemJailer", "SIGSTOP_FREEZE", 
                "PID: " + std::to_string(pid), "cgroup failed. Process suspended via SIGSTOP."
            );
        }
    }

    // 3. ABSOLUTE CONTAINMENT: SIGKILL (Fail-Secure)
    // If we can't throttle or freeze it, we terminate it to protect the mesh.
    if (!contained) {
        if (kill(pid, SIGKILL) == 0) {
            telemetry::AuditLogger::emit_json(
                telemetry::AuditLevel::CRITICAL, "SystemJailer", "SIGKILL_TERMINATE", 
                "PID: " + std::to_string(pid), "Non-suspendable threat. Process terminated."
            );
            return true; // Return true because the threat is neutralized
        }
    }

    return contained;
}

} // namespace neuro_mesh::defense
