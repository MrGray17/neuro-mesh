// ============================================================
// NEURO-MESH : PURE PBFT DOMAIN LOGIC
// ============================================================
#pragma once
#include <string>
#include <set>
#include <cstdint>
#include <algorithm>

namespace neuro_mesh::domain::pbft {

enum class Phase { IDLE, WAITING_PREPARE, WAITING_COMMIT, DECIDED };

// Pure, stateless function. Math dictates N >= 3f + 1. 
// WHY: We compute the exact quorum required to tolerate 'f' malicious nodes.
[[nodiscard]] constexpr size_t calculate_quorum(size_t total_nodes) noexcept {
    if (total_nodes < 4) return total_nodes; // Degraded state fallback
    size_t f = (total_nodes - 1) / 3;
    return (2 * f) + 1;
}

struct ConsensusInstance {
    uint64_t view{0};
    uint64_t seq{0};
    std::string digest;
    Phase phase{Phase::IDLE};
    
    std::set<std::string> prepare_votes;
    std::set<std::string> commit_votes;
    
    bool is_decided{false};

    // Immutable state transitions
    [[nodiscard]] bool register_prepare_vote(const std::string& node_id, size_t total_network_nodes) {
        if (phase != Phase::WAITING_COMMIT) return false;
        prepare_votes.insert(node_id);
        
        if (prepare_votes.size() >= calculate_quorum(total_network_nodes)) {
            phase = Phase::DECIDED; // Ready to transition to COMMIT broadcast
            return true;
        }
        return false;
    }

    [[nodiscard]] bool register_commit_vote(const std::string& node_id, size_t total_network_nodes) {
        if (is_decided) return false;
        commit_votes.insert(node_id);
        
        if (commit_votes.size() >= calculate_quorum(total_network_nodes)) {
            is_decided = true;
            return true;
        }
        return false;
    }
};

} // namespace neuro_mesh::domain::pbft
