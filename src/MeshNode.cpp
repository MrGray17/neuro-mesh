#include "MeshNode.hpp"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

namespace neuro_mesh::network {

MeshNode::MeshNode(uint16_t port, ai::InferenceEngine& engine) 
    : m_server_fd(-1), m_port(port), m_engine(engine) {
    
    m_server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    
    memset(&m_c2_addr, 0, sizeof(m_c2_addr));
    m_c2_addr.sin_family = AF_INET;
    // 🔥 FIX 2A: Unify the telemetry port to match the AI Cortex (9998)
    m_c2_addr.sin_port = htons(9998); 
    inet_pton(AF_INET, "127.0.0.1", &m_c2_addr.sin_addr);
}

MeshNode::~MeshNode() {
    if (m_server_fd >= 0) close(m_server_fd);
}

void MeshNode::heartbeat(const std::string& node_id) {
    std::string ai_status = m_engine.is_operational() ? "ACTIVE" : "WARMING_UP";
    
    // 🔥 FIX 2B: Standardize the JSON keys for the React UI and add the TELEMETRY: prefix
    std::string msg = "TELEMETRY:{\"ID\":\"" + node_id + 
                      "\",\"HOST\":\"Sovereign_Agent\",\"RAM_MB\":15,\"CPU_LOAD\":2.5,"
                      "\"PROCS\":1,\"NET_OUT\":0,\"STATUS\":\"STABLE\","
                      "\"STATE\":\"NORMAL\",\"NEIGHBORS\":\"\"}";
    
    sendto(m_server_fd, msg.c_str(), msg.length(), 0, 
           (struct sockaddr*)&m_c2_addr, sizeof(m_c2_addr));
}

void MeshNode::start() {
    std::cout << "[MESH_NODE] Subsystem online on port " << m_port << std::endl;
}

void MeshNode::stop() {
    std::cout << "[MESH_NODE] Subsystem offline." << std::endl;
}

} // namespace neuro_mesh::network
