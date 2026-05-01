// ============================================================
// NEURO-MESH : AI INFERENCE ENGINE (STABLE Z-SCORE EDITION)
// ============================================================
#include "InferenceEngine.hpp"
#include <algorithm>
#include <map>
#include <cmath>
#include <numeric>

namespace neuro_mesh::ai {

InferenceEngine::InferenceEngine(size_t window_size) 
    : m_window_size(window_size), m_mean(0.0), m_stddev(0.1) {
    // We initialize stddev to 0.1 to avoid immediate volatility before warmup
}

double InferenceEngine::calculate_entropy(const std::string& data) const {
    if (data.empty()) return 0.0;
    
    std::map<char, int> frequencies;
    for (char c : data) frequencies[c]++;

    double entropy = 0.0;
    double len = static_cast<double>(data.size());
    
    for (auto const& [chars, count] : frequencies) {
        double p = static_cast<double>(count) / len;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

void InferenceEngine::update_baseline(double new_value) {
    m_entropy_history.push_back(new_value);
    if (m_entropy_history.size() > m_window_size) {
        m_entropy_history.pop_front();
    }

    if (m_entropy_history.empty()) return;

    // Calculate robust Mean
    double sum = std::accumulate(m_entropy_history.begin(), m_entropy_history.end(), 0.0);
    m_mean = sum / m_entropy_history.size();

    // Calculate StdDev with Laplacian Smoothing (Variance + 0.0001)
    double sq_sum = 0.0;
    for (double val : m_entropy_history) {
        sq_sum += (val - m_mean) * (val - m_mean);
    }
    
    // We add a tiny epsilon (smoothing) to the variance to prevent division by zero
    double variance = (sq_sum / m_entropy_history.size()) + 0.0001;
    m_stddev = std::sqrt(variance);
}

bool InferenceEngine::analyze(const std::string& comm, const std::string& payload) {
    // 1. Immutable Blacklist Check (Zero-Latency Hit)
    // Using C++20 contains() for O(log n) lookup
    if (m_blacklist.contains(comm) || m_blacklist.contains(payload)) {
        return true; 
    }

    // 2. Entropy Feature Engineering
    // We analyze the combined signature of the process name and its payload
    double current_entropy = calculate_entropy(comm + payload);
    
    bool is_anomaly = false;

    // 3. Warmup Logic
    if (m_entropy_history.size() < 10) {
        // Learning phase: We record but don't isolate yet to avoid booting errors
        update_baseline(current_entropy);
        return false;
    }

    // 4. Clamped Z-Score Analysis
    // We ensure m_stddev is never so low that it creates false positives
    double effective_sigma = std::max(m_stddev, 0.05);
    double z_score = std::abs(current_entropy - m_mean) / effective_sigma;

    if (z_score > m_threshold) {
        // Statistical anomaly detected
        is_anomaly = true;
    }

    // 5. Reinforcement Learning
    // Only update baseline if the data is "Normal" to prevent baseline poisoning
    if (!is_anomaly) {
        update_baseline(current_entropy);
    }

    return is_anomaly;
}

void InferenceEngine::add_to_blacklist(const std::string& signature) {
    if (!signature.empty() && signature.length() > 2) {
        m_blacklist.insert(signature);
    }
}

} // namespace neuro_mesh::ai
