#pragma once
#include <vector>
#include <mutex>
#include <sys/types.h>

namespace neuro_mesh::core {

// 🛡️ THE FIX: Struct to hold the secure file descriptor
struct JailedProcess {
    pid_t pid;
    int pidfd; 
};

class SystemJailer {
public:
    SystemJailer() = default;
    ~SystemJailer(); // Requires custom destructor to close fds

    void imprison(pid_t pid);
    
    // 🛡️ THE FIX: Explicit Domain Naming
    void eradicate_threats(); 

private:
    std::vector<JailedProcess> m_jailed_processes;
    std::mutex m_jail_mutex;
};

} // namespace neuro_mesh::core
