#include "SystemJailer.hpp"
#include <iostream>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>

namespace neuro_mesh::core {

SystemJailer::~SystemJailer() {
    std::lock_guard<std::mutex> lock(m_jail_mutex);
    for (auto& jp : m_jailed_processes) {
        if (jp.pidfd >= 0) {
            close(jp.pidfd);
        }
    }
    m_jailed_processes.clear();
}

void SystemJailer::imprison(pid_t pid) {
    if (pid <= 0) return;
    
    // Acquire secure handle to prevent PID reuse attacks
    int pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
    if (pidfd < 0) {
        kill(pid, SIGSTOP); // Legacy fallback
        return;
    }

    // Suspend process at the kernel level
    if (syscall(SYS_pidfd_send_signal, pidfd, SIGSTOP, NULL, 0) == 0) {
        std::lock_guard<std::mutex> lock(m_jail_mutex);
        m_jailed_processes.push_back({pid, pidfd});
        std::cout << "\033[1;41;37m[JAILER] Process " << pid << " imprisoned via pidfd.\033[0m" << std::endl;
    } else {
        close(pidfd);
    }
}

void SystemJailer::eradicate_threats() {
    std::lock_guard<std::mutex> lock(m_jail_mutex);
    if (m_jailed_processes.empty()) return;

    for (auto& jp : m_jailed_processes) {
        if (jp.pidfd >= 0) {
            syscall(SYS_pidfd_send_signal, jp.pidfd, SIGKILL, NULL, 0);
            close(jp.pidfd);
        } else {
            kill(jp.pid, SIGKILL);
        }
    }
    m_jailed_processes.clear();
    std::cout << "[JAILER] All imprisoned threats purged." << std::endl;
}

} // namespace neuro_mesh::core
