#pragma once
#include <vector>
#include <mutex>
#include <sys/types.h>

namespace neuro_mesh::core {

class SystemJailer {
public:
    SystemJailer() = default;
    ~SystemJailer() = default;

    void imprison(pid_t pid);
    void release_all(); // NEW: The Vaccination mechanism

private:
    std::vector<pid_t> m_jailed_pids;
    std::mutex m_jail_mutex;
};

} // namespace neuro_mesh::core
