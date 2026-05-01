#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <netinet/in.h>
#include "InferenceEngine.hpp" // Brain integration

namespace neuro_mesh::network {

struct ThreatSignature {
    char payload_name[64];
    double entropy_score;
    uint32_t origin_node_id;
};

class MeshNode {
public:
    MeshNode(uint16_t port, ai::InferenceEngine& engine);
    ~MeshNode();

    void start_listening();
    void broadcast_threat(const ThreatSignature& sig);
    void add_peer(const std::string& ip, uint16_t port);

private:
    void listen_loop();
    
    uint16_t m_port;
    int m_server_fd;
    std::atomic<bool> m_active{true};
    std::thread m_listener_thread;
    ai::InferenceEngine& m_engine; // Reference to the brain
    
    struct Peer {
        std::string ip;
        uint16_t port;
    };
    std::vector<Peer> m_peers;
};

} // namespace neuro_mesh::network
