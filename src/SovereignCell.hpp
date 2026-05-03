// ============================================================
// NEURO-MESH : SOVEREIGN CELL (LOCK-FREE EDITION)
// ============================================================
#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <chrono>
#include <queue>
#include <mutex>
#include <condition_variable>
#include "InferenceEngine.hpp"
#include "MeshNode.hpp"
#include "SystemJailer.hpp"

struct ring_buffer;
struct sensor_bpf;

namespace neuro_mesh::core {

// Domain Entity
struct KernelEventData {
    uint32_t pid;
    uint32_t event_type;
    char comm[16];
    char payload[256];
};

// Thread-safe Multi-Producer Single-Consumer Queue
template<typename T>
class TelemetryQueue {
private:
    std::queue<T> m_queue;
    std::mutex m_mux;
    std::condition_variable m_cv;
    const size_t m_max_size = 5000; // Deep buffer for burst traffic
public:
    void push(T event) noexcept {
        std::lock_guard<std::mutex> lock(m_mux);
        if (m_queue.size() < m_max_size) {
            m_queue.push(std::move(event));
            m_cv.notify_one();
        }
    }
    bool pop(T& out, std::atomic<bool>& running) noexcept {
        std::unique_lock<std::mutex> lock(m_mux);
        m_cv.wait_for(lock, std::chrono::milliseconds(50), [&]{ 
            return !m_queue.empty() || !running.load(); 
        });
        if (m_queue.empty()) return false;
        out = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }
};

class SovereignCell {
public:
    struct Result {
        std::unique_ptr<SovereignCell> cell;
        std::string error;
    };

    static Result create(const std::string& node_id);
    ~SovereignCell();

    void run(std::atomic<bool>* shutdown_flag, std::atomic<bool>* vaccine_flag) noexcept;
    void trigger_shutdown() noexcept;
    void vaccinate() noexcept;

private:
    explicit SovereignCell(std::string id);
    std::string load_and_attach_ebpf();
    static int handle_ringbuf_event(void *ctx, void *data, size_t size);
    
    void telemetry_loop() noexcept;
    void broadcaster_loop(std::atomic<bool>* shutdown_flag) noexcept;

    std::string m_node_id;
    std::atomic<bool> m_running{true};
    std::thread m_telemetry_thread;
    std::thread m_broadcaster_thread;

    TelemetryQueue<KernelEventData> m_internal_queue;

    ai::InferenceEngine m_brain;
    network::MeshNode m_mesh_node;
    SystemJailer m_jailer;

    sensor_bpf* m_skel = nullptr;
    ring_buffer* m_ringbuf = nullptr;

    std::atomic<std::chrono::steady_clock::time_point> m_immunity_until{std::chrono::steady_clock::now()};
};

} // namespace neuro_mesh::core
