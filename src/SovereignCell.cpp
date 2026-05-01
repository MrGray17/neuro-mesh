#include "SovereignCell.hpp"
#include "AuditLogger.hpp"
#include "sensor.skel.h" 
#include <iostream>
#include <cstring> 
#include <fstream>
#include <chrono>

namespace neuro_mesh::core {

SovereignCell::SovereignCell(std::string id) : m_node_id(std::move(id)), m_brain(100), m_mesh_node(50051, m_brain) {
    m_telemetry_thread = std::thread(&SovereignCell::telemetry_loop, this);
}

SovereignCell::~SovereignCell() {
    m_running.store(false);
    if (m_telemetry_thread.joinable()) m_telemetry_thread.join();
    if (m_ringbuf) ring_buffer__free(m_ringbuf);
    if (m_skel) sensor_bpf__destroy(m_skel);
}

SovereignCell::Result SovereignCell::create(const std::string& node_id) {
    auto cell = std::unique_ptr<SovereignCell>(new SovereignCell(node_id));
    std::string err = cell->load_and_attach_ebpf();
    if (!err.empty()) return {nullptr, err};
    
    cell->m_mesh_node.start_listening();
    telemetry::AuditLogger::emit_json(telemetry::AuditLevel::INFO, "SovereignCell", "INITIALIZED", node_id, "Eyes, Brain, Hands, and Mesh integrated.");
    return {std::move(cell), ""};
}

std::string SovereignCell::load_and_attach_ebpf() {
    m_skel = sensor_bpf__open_and_load();
    if (!m_skel) return "eBPF Load Failed.";
    if (sensor_bpf__attach(m_skel) != 0) return "eBPF Attach Failed.";
    int map_fd = bpf_map__fd(m_skel->maps.telemetry_ringbuf);
    m_ringbuf = ring_buffer__new(map_fd, handle_ringbuf_event, this, NULL);
    if (!m_ringbuf) return "Ringbuf Creation Failed.";
    return "";
}

int SovereignCell::handle_ringbuf_event(void *ctx, void *data, size_t size) {
    (void)size;
    auto* cell = static_cast<SovereignCell*>(ctx);
    auto* event = static_cast<KernelEvent*>(data);
    
    bool is_anomaly = cell->m_brain.analyze(event->comm, event->payload);
    std::string action = (event->event_type == 1) ? "EXEC" : "CONNECT";
    
    if (is_anomaly) {
        telemetry::AuditLogger::emit_json(telemetry::AuditLevel::CRITICAL, "InferenceEngine", "ANOMALY_DETECTED", "PID: " + std::to_string(event->pid), "Entropy/Blacklist violation in " + std::string(event->payload));
        cell->m_jailer.imprison(event->pid);
        
        network::ThreatSignature sig;
        strncpy(sig.payload_name, event->payload, sizeof(sig.payload_name) - 1);
        sig.payload_name[sizeof(sig.payload_name) - 1] = '\0';
        sig.entropy_score = 9.9;
        sig.origin_node_id = 1;
        cell->m_mesh_node.broadcast_threat(sig);
    } else {
        telemetry::AuditLogger::emit_json(telemetry::AuditLevel::INFO, "KernelProbe", action, "PID: " + std::to_string(event->pid), event->payload);
    }
    return 0;
}

void SovereignCell::run() noexcept {
    while (m_running.load()) ring_buffer__poll(m_ringbuf, 100);
}

void SovereignCell::trigger_shutdown() noexcept { m_running.store(false); }

void SovereignCell::telemetry_loop() {
    while (m_running.load()) {
        double cpu_usage = (rand() % 15) + 5.0; // Simulated CPU load for UI animation
        double ram_mb = 0.0;

        std::ifstream meminfo("/proc/meminfo");
        std::string line;
        long total_ram = 0, free_ram = 0;
        while (std::getline(meminfo, line)) {
            if (line.find("MemTotal:") == 0) sscanf(line.c_str(), "MemTotal: %ld kB", &total_ram);
            if (line.find("MemAvailable:") == 0) sscanf(line.c_str(), "MemAvailable: %ld kB", &free_ram);
        }
        if (total_ram > 0) ram_mb = (total_ram - free_ram) / 1024.0;

        telemetry::AuditLogger::emit_metric(cpu_usage, static_cast<int>(ram_mb), 1);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

} // namespace neuro_mesh::core
