// ============================================================
// NEURO-MESH : INFERENCE ENGINE (V7.2 PAYLOAD SCAN FIX)
// ============================================================
#include "InferenceEngine.hpp"
#include <cmath>
#include <numeric>
#include <algorithm>
#include <map>

namespace neuro_mesh::ai {

InferenceEngine::InferenceEngine(size_t window_size) 
    : m_window_size(window_size), m_mean(0.0), m_stddev(0.1) {
    m_blacklist = {"nc", "ncat", "reverse_shell", "metasploit"};
}

bool InferenceEngine::is_operational() const noexcept {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    return m_entropy_history.size() >= (m_window_size / 10); 
}

double InferenceEngine::calculate_entropy(const std::string& data) const {
    if (data.empty()) return 0.0;
    std::map<char, int> counts;
    for (char c : data) counts[c]++;
    
    double entropy = 0.0;
    for (auto const& [ch, count] : counts) {
        double p = (double)count / data.length();
        entropy -= p * std::log2(p);
    }
    return entropy;
}

void InferenceEngine::update_baseline(double new_value) {
    m_entropy_history.push_back(new_value);
    if (m_entropy_history.size() > m_window_size) {
        m_entropy_history.pop_front();
    }
    
    double sum = std::accumulate(m_entropy_history.begin(), m_entropy_history.end(), 0.0);
    m_mean = sum / m_entropy_history.size();
    
    double sq_sum = 0.0;
    for (double val : m_entropy_history) {
        sq_sum += (val - m_mean) * (val - m_mean);
    }
    m_stddev = std::sqrt(sq_sum / m_entropy_history.size()) + 0.0001;
}

bool InferenceEngine::analyze(const std::string& comm, const std::string& payload) {
    std::lock_guard<std::mutex> lock(m_state_mutex);
    
    // 1. Check the Caller (e.g., if netcat itself spawns a child)
    if (m_blacklist.contains(comm)) return true;

    // 🔥 THE REALITY FIX: Scan the Payload (the binary being executed)
    for (const auto& threat : m_blacklist) {
        if (payload.find(threat) != std::string::npos) {
            return true; // Target matched in the execution path
        }
    }

    // 3. Fallback to Deep Entropy Analysis
    double entropy = calculate_entropy(payload);
    double z_score = std::abs(entropy - m_mean) / m_stddev;
    
    update_baseline(entropy);
    return (z_score > 3.0 && m_entropy_history.size() >= m_window_size);
}

} // namespace neuro_mesh::ai
