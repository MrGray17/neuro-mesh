#pragma once
#include <memory>
#include <string>
#include <atomic>
#include <thread> // Required for hardware monitor
#include <bpf/libbpf.h>
#include "InferenceEngine.hpp"
#include "SystemJailer.hpp"
#include "MeshNode.hpp"

struct sensor_bpf;
struct ring_buffer;

namespace neuro_mesh::core {

struct KernelEvent {
    uint32_t pid;
    uint32_t ppid;
    uint32_t event_type;
    char comm[16];
    char payload[256];
};

class SovereignCell {
public:
    struct Result {
        std::unique_ptr<SovereignCell> cell;
        std::string error;
    };

    static Result create(const std::string& node_id);
    ~SovereignCell();
    void run() noexcept;
    void trigger_shutdown() noexcept;

private:
    explicit SovereignCell(std::string id);
    std::string load_and_attach_ebpf(); 
    static int handle_ringbuf_event(void *ctx, void *data, size_t size);
    
    void telemetry_loop(); // Background hardware monitor loop

    std::string m_node_id;
    std::atomic<bool> m_running{true};
    std::thread m_telemetry_thread; // Hardware monitor thread
    
    ::sensor_bpf* m_skel{nullptr};
    ::ring_buffer* m_ringbuf{nullptr};

    ai::InferenceEngine m_brain;
    defense::SystemJailer m_jailer;
    network::MeshNode m_mesh_node;
};

} // namespace neuro_mesh::core
