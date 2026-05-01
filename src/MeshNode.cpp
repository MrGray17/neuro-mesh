#include "MeshNode.hpp"
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace neuro_mesh::network {

MeshNode::MeshNode(uint16_t port, ai::InferenceEngine& engine) 
    : m_port(port), m_server_fd(-1), m_engine(engine) {}

MeshNode::~MeshNode() {
    m_active = false;
    if (m_server_fd != -1) close(m_server_fd);
    if (m_listener_thread.joinable()) m_listener_thread.join();
}

void MeshNode::start_listening() {
    m_server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_server_fd < 0) {
        std::cerr << "[MESH_NODE] Failed to create UDP socket.\n";
        return;
    }

    struct sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(m_port);

    if (bind(m_server_fd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        std::cerr << "[MESH_NODE] Bind failed on port " << m_port << "\n";
        return;
    }

    std::cout << "[MESH_NODE] 🌐 Nerve System Online. Listening for Mesh Intelligence on UDP " << m_port << "\n";
    m_listener_thread = std::thread(&MeshNode::listen_loop, this);
}

void MeshNode::broadcast_threat(const ThreatSignature& sig) {
    std::cout << "\n[MESH_NODE] 🌐 BROADCASTING THREAT TO PEERS: " 
              << sig.payload_name << " (Score: " << sig.entropy_score << ")\n";
    
    for (const auto& peer : m_peers) {
        struct sockaddr_in peer_addr{};
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(peer.port);
        inet_pton(AF_INET, peer.ip.c_str(), &peer_addr.sin_addr);

        sendto(m_server_fd, &sig, sizeof(ThreatSignature), 0, 
               (const struct sockaddr *)&peer_addr, sizeof(peer_addr));
    }
}

void MeshNode::add_peer(const std::string& ip, uint16_t port) {
    m_peers.push_back({ip, port});
    std::cout << "[MESH_NODE] 🔗 Peer added to Mesh: " << ip << ":" << port << "\n";
}

void MeshNode::listen_loop() {
    char buffer[1024];
    while (m_active.load()) {
        struct sockaddr_in cliaddr{};
        socklen_t len = sizeof(cliaddr);
        
        int n = recvfrom(m_server_fd, (char *)buffer, 1024, MSG_DONTWAIT, (struct sockaddr *)&cliaddr, &len);
        
        if (n == sizeof(ThreatSignature)) {
            auto* incoming_sig = reinterpret_cast<ThreatSignature*>(buffer);
            std::cout << "\n[MESH_NODE] ⚠️ INCOMING INTELLIGENCE FROM MESH: Hostile Payload ["
                      << incoming_sig->payload_name << "] detected by Node " 
                      << incoming_sig->origin_node_id << "!\n";
                      
            // 🔥 DYNAMIC VACCINATION: Inject the mesh threat into the local brain
            m_engine.add_to_blacklist(incoming_sig->payload_name);
            
            std::cout << "[MESH_NODE] 💉 VACCINATED: Signature [" 
                      << incoming_sig->payload_name << "] blacklisted locally.\n";
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); 
        }
    }
}

} // namespace neuro_mesh::network
