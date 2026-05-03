// ============================================================
// NEURO-MESH : SOVEREIGN CELL (V7.5 THREAD-SAFE EDGE)
// ============================================================
#include "SovereignCell.hpp"
#include "sensor.skel.h"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <nlohmann/json.hpp>
#include <sys/sysinfo.h>
#include <cstdlib>

extern std::atomic<bool> g_vaccine_requested;

// 🔥 THE FIX: A dedicated atomic bridge between the two internal threads
static std::atomic<bool> s_force_stable{false}; 

namespace neuro_mesh::core {

SovereignCell::SovereignCell(std::string id) 
    : m_node_id(std::move(id)), m_brain(100), m_mesh_node(5000, m_brain), m_jailer() {}

SovereignCell::~SovereignCell() { trigger_shutdown(); }

SovereignCell::Result SovereignCell::create(const std::string& node_id) {
    auto cell = std::unique_ptr<SovereignCell>(new SovereignCell(node_id));
    if (!cell->load_and_attach_ebpf().empty()) return {nullptr, "eBPF Error"};
    
    cell->m_telemetry_thread = std::thread(&SovereignCell::telemetry_loop, cell.get());
    return {std::move(cell), ""};
}

std::string SovereignCell::load_and_attach_ebpf() {
    m_skel = sensor_bpf__open_and_load();
    if (!m_skel) return "Fail";
    sensor_bpf__attach(m_skel);
    m_ringbuf = ring_buffer__new(bpf_map__fd(m_skel->maps.telemetry_ringbuf), handle_ringbuf_event, this, nullptr);
    return "";
}

void SovereignCell::telemetry_loop() noexcept {
    int udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in c2_addr{};
    c2_addr.sin_family = AF_INET;
    c2_addr.sin_port = htons(9998);
    inet_pton(AF_INET, "127.0.0.1", &c2_addr.sin_addr);

    KernelEventData event;
    bool is_isolated_state = false;
    auto agent_boot_time = std::chrono::steady_clock::now();
    const int SYSTEM_ARMING_DELAY_SEC = 45;

    int node_index = 0;
    if (const char* env_idx = std::getenv("NEURO_NODE_INDEX")) {
        node_index = std::stoi(env_idx);
    }

    while (m_running.load()) {
        // 🔥 THE FIX: Safely consume the bridge flag without race conditions
        if (s_force_stable.exchange(false)) {
            is_isolated_state = false;
        }

        auto now = std::chrono::steady_clock::now();
        int uptime_sec = std::chrono::duration_cast<std::chrono::seconds>(now - agent_boot_time).count();
        bool system_armed = (uptime_sec >= SYSTEM_ARMING_DELAY_SEC);

        if (m_ringbuf) ring_buffer__poll(m_ringbuf, 10);
        
        bool threat_this_tick = false;
        while (m_internal_queue.pop(event, m_running)) {
            if ((event.pid % 3) != (node_index % 3)) continue; 

            if (m_brain.analyze(event.comm, event.payload)) {
                if (system_armed) {
                    threat_this_tick = true;
                    is_isolated_state = true;
                    m_jailer.imprison(event.pid);
                }
            }
        }

        struct sysinfo memInfo; sysinfo(&memInfo);
        long ram = (memInfo.totalram - memInfo.freeram) / (1024 * 1024);
        double loads[1]; double cpu = (getloadavg(loads, 1) != -1) ? loads[0] : 0.0;

        nlohmann::json j;
        j["ID"] = m_node_id;
        j["RAM_MB"] = ram;
        j["CPU_LOAD"] = cpu;
        j["PROCS"] = 1;
        j["NET_OUT"] = 0;
        j["KERNEL_THREAT"] = threat_this_tick ? "TRUE" : "FALSE";
        j["STATUS"] = is_isolated_state ? "SELF_ISOLATED" : "STABLE";

        std::string payload = "TELEMETRY:" + j.dump();
        sendto(udp_sock, payload.c_str(), payload.length(), 0, (struct sockaddr*)&c2_addr, sizeof(c2_addr));
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    close(udp_sock);
}

void SovereignCell::run(std::atomic<bool>* shutdown_flag, std::atomic<bool>* vaccine_flag) noexcept {
    while (m_running.load() && !shutdown_flag->load()) {
        if (vaccine_flag->load()) { 
            m_jailer.eradicate_threats(); 
            std::cout << "\033[1;32m[GUÉRISON]\033[0m Kernel Jail purged. Agent restored.\n";
            
            // 🔥 THE FIX: Arm the internal bridge flag so the telemetry thread is guaranteed to see it
            s_force_stable.store(true); 
            vaccine_flag->store(false); 
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void SovereignCell::trigger_shutdown() noexcept {
    if (m_running.exchange(false)) {
        if (m_telemetry_thread.joinable()) m_telemetry_thread.join();
        if (m_skel) sensor_bpf__destroy(m_skel);
    }
}

int SovereignCell::handle_ringbuf_event(void *ctx, void *data, size_t) {
    auto* self = static_cast<SovereignCell*>(ctx);
    self->m_internal_queue.push(*(static_cast<KernelEventData*>(data)));
    return 0;
}

} // namespace neuro_mesh::core
