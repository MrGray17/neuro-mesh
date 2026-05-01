#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono> // Required for the Immunity Clock
#include "InferenceEngine.hpp"
#include "MeshNode.hpp"
#include "SystemJailer.hpp"

struct ring_buffer;
struct sensor_bpf;

namespace neuro_mesh::core {

class SovereignCell {
public:
    struct Result {
        std::unique_ptr<SovereignCell> cell;
        std::string error;
    };

    static Result create(const std::string& node_id);
    ~SovereignCell();

    // UPDATED: Now safely accepts atomic flags from the main POSIX signal handler
    void run(std::atomic<bool>* shutdown_flag, std::atomic<bool>* vaccine_flag) noexcept;
    
    void trigger_shutdown() noexcept;
    void vaccinate();

private:
    explicit SovereignCell(std::string id);
    std::string load_and_attach_ebpf();
    static int handle_ringbuf_event(void *ctx, void *data, size_t size);
    void telemetry_loop();

    std::string m_node_id;
    std::atomic<bool> m_running{true};
    std::thread m_telemetry_thread;

    ai::InferenceEngine m_brain;
    network::MeshNode m_mesh_node;
    SystemJailer m_jailer;

    sensor_bpf* m_skel = nullptr;
    ring_buffer* m_ringbuf = nullptr;

    // THE SHIELD: Tracks how long the agent should ignore the ring buffer backlog
    std::atomic<std::chrono::steady_clock::time_point> m_immunity_until{std::chrono::steady_clock::now()};
};

} // namespace neuro_mesh::core
