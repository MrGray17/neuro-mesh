#pragma once
#include <string>
#include <netinet/in.h>
#include "InferenceEngine.hpp"

namespace neuro_mesh::network {

class MeshNode {
public:
    MeshNode(uint16_t port, ai::InferenceEngine& engine);
    ~MeshNode();

    void heartbeat(const std::string& node_id);
    void start();
    void stop();

private:
    int m_server_fd;
    uint16_t m_port;
    ai::InferenceEngine& m_engine;
    struct sockaddr_in m_c2_addr;
};

} // namespace neuro_mesh::network
