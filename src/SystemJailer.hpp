/**
 * @file SystemJailer.hpp
 * @brief Deterministic process containment using cgroups v2.
 */

#pragma once
#include <string>
#include <filesystem>
#include <expected>

namespace neuro_mesh::defense {

enum class JailError {
    CGROUP_SETUP_FAILED,
    ATTACH_FAILED,
    RESOURCE_LIMIT_FAILED,
    PID_NOT_FOUND
};

class SystemJailer {
public:
    SystemJailer();
    ~SystemJailer();

    /**
     * @brief Imprisons a PID in a restricted cgroup with 0.01% CPU and no network.
     */
    bool imprison(uint32_t pid);

private:
    std::filesystem::path m_jail_path;
    bool initialize_base_cgroup();
};

} // namespace neuro_mesh::defense
