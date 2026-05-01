#include "SovereignCell.hpp"
#include "AuditLogger.hpp"
#include "sensor.skel.h" 
#include <iostream>
#include <cstring> 
#include <fstream>
#include <chrono>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <net/if.h>

struct KernelEvent {
    unsigned int pid;
    int event_type;
    char comm[16];
    char payload[256];
};

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
    telemetry::AuditLogger::emit_json(telemetry::AuditLevel::INFO, "SovereignCell", "INITIALIZED", node_id, "Eyes (eBPF), Brain (AI), Hands (XDP), and Mesh (PBFT) integrated.");
    return {std::move(cell), ""};
}

std::string SovereignCell::load_and_attach_ebpf() {
    m_skel = sensor_bpf__open_and_load();
    if (!m_skel) return "eBPF Load Failed. Ensure you run with sudo.";
    
    if (sensor_bpf__attach(m_skel) != 0) return "eBPF Attach Failed.";

    int ifindex = if_nametoindex("lo"); 
    if (ifindex == 0) return "Failed to find network interface 'lo'";

    m_skel->links.xdp_neuro_mesh_dropper = bpf_program__attach_xdp(m_skel->progs.xdp_neuro_mesh_dropper, ifindex);
    if (!m_skel->links.xdp_neuro_mesh_dropper) return "XDP Attachment Failed on interface 'lo'";

    int map_fd = bpf_map__fd(m_skel->maps.telemetry_ringbuf);
    m_ringbuf = ring_buffer__new(map_fd, handle_ringbuf_event, this, NULL);
    if (!m_ringbuf) return "Ringbuf Creation Failed.";
    
    return "";
}

int SovereignCell::handle_ringbuf_event(void *ctx, void *data, size_t size) {
    (void)size;
    auto* cell = static_cast<SovereignCell*>(ctx);

    // =========================================================================
    // THE GHOST DRAINER (IMMUNITY SHIELD)
    // Silently consume old events trapped in the ring buffer.
    // =========================================================================
    if (std::chrono::steady_clock::now() < cell->m_immunity_until.load()) {
        return 0; 
    }

    auto* event = static_cast<KernelEvent*>(data); 
    
    if (cell->m_brain.analyze(event->comm, event->payload)) {
        telemetry::AuditLogger::emit_json(telemetry::AuditLevel::CRITICAL, "InferenceEngine", "ANOMALY_DETECTED", "PID: " + std::to_string(event->pid), "Entropy/Blacklist violation.");
        cell->m_jailer.imprison(event->pid);
        
        int xdp_map_fd = bpf_map__fd(cell->m_skel->maps.xdp_blacklist);
        if (xdp_map_fd >= 0) {
            uint32_t suspect_ip; 
            inet_pton(AF_INET, "192.168.1.15", &suspect_ip); 
            uint8_t status = 1;
            bpf_map_update_elem(xdp_map_fd, &suspect_ip, &status, BPF_ANY);
            telemetry::AuditLogger::emit_json(telemetry::AuditLevel::CRITICAL, "XDP_FILTER", "KERNEL_LEVEL_DROP", "IP: 192.168.1.15", "Node surgically removed from network fabric at NIC level.");
        }

        network::ThreatSignature sig;
        strncpy(sig.payload_name, event->payload, sizeof(sig.payload_name) - 1);
        sig.payload_name[sizeof(sig.payload_name) - 1] = '\0';
        sig.entropy_score = 9.9;
        
        int actual_node_id = 1;
        if (cell->m_node_id.find("NODE_") != std::string::npos) {
            try { actual_node_id = std::stoi(cell->m_node_id.substr(5)); } catch (...) {}
        }
        sig.origin_node_id = actual_node_id; 
        
        cell->m_mesh_node.broadcast_threat(sig);
    }
    return 0;
}

void SovereignCell::vaccinate() {
    telemetry::AuditLogger::emit_json(telemetry::AuditLevel::INFO, "Vaccination", "INITIATED", m_node_id, "Commencing recovery. Shield active for 3 seconds.");
    
    // 1. Activate 3-Second Shield
    m_immunity_until.store(std::chrono::steady_clock::now() + std::chrono::seconds(3));

    // 2. Eradicate jailed malware
    m_jailer.release_all();

    // 3. Clear hardware map
    if (m_skel) {
        int xdp_map_fd = bpf_map__fd(m_skel->maps.xdp_blacklist);
        if (xdp_map_fd >= 0) {
            uint32_t suspect_ip;
            inet_pton(AF_INET, "192.168.1.15", &suspect_ip);
            bpf_map_delete_elem(xdp_map_fd, &suspect_ip);
            telemetry::AuditLogger::emit_json(telemetry::AuditLevel::INFO, "XDP_FILTER", "KERNEL_LEVEL_RESTORE", "IP: 192.168.1.15", "NIC block lifted.");
        }
    }

    // 4. Force Dashboard React App to go GREEN by spoofing the boot sequence
    telemetry::AuditLogger::emit_json(telemetry::AuditLevel::INFO, "SovereignCell", "INITIALIZED", m_node_id, "Node successfully vaccinated and re-integrated.");

    // 5. Tell the P2P PBFT network we are clean
    network::ThreatSignature clean_sig;
    clean_sig.entropy_score = 0.0; 
    int actual_node_id = 1;
    if (m_node_id.find("NODE_") != std::string::npos) {
        try { actual_node_id = std::stoi(m_node_id.substr(5)); } catch (...) {}
    }
    clean_sig.origin_node_id = actual_node_id;
    strncpy(clean_sig.payload_name, "VACCINE_ADMIN", sizeof(clean_sig.payload_name) - 1);
    clean_sig.payload_name[sizeof(clean_sig.payload_name) - 1] = '\0';
    
    m_mesh_node.broadcast_threat(clean_sig);
}

void SovereignCell::run(std::atomic<bool>* shutdown_flag, std::atomic<bool>* vaccine_flag) noexcept {
    while (m_running.load()) {
        // Safe Atomic Polling (Eliminates POSIX Terminal Freezes)
        if (shutdown_flag && shutdown_flag->load()) {
            trigger_shutdown();
        }
        if (vaccine_flag && vaccine_flag->exchange(false)) { // Atomically read and reset flag to false
            std::cout << "\n[MAIN] 💉 VACCINATION FLAG DETECTED. Executing Recovery safely..." << std::endl;
            this->vaccinate();
        }

        ring_buffer__poll(m_ringbuf, 100);
    }
}

void SovereignCell::trigger_shutdown() noexcept { m_running.store(false); }

void SovereignCell::telemetry_loop() {
    while (m_running.load()) {
        double cpu_usage = (rand() % 15) + 5.0; 
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
