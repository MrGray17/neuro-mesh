#pragma once
#include <string>
#include <deque>
#include <numeric>
#include <cmath>
#include <set> // Added for blacklist

namespace neuro_mesh::ai {

class InferenceEngine {
public:
    explicit InferenceEngine(size_t window_size);
    bool analyze(const std::string& comm, const std::string& payload);
    void add_to_blacklist(const std::string& signature); // The "Vaccination" method

private:
    double calculate_entropy(const std::string& data) const;
    void update_baseline(double new_value);

    size_t m_window_size;
    std::deque<double> m_entropy_history;
    std::set<std::string> m_blacklist; // Known-evil signatures
    
    double m_mean{0.0};
    double m_stddev{0.0};
    const double m_threshold{2.5}; 
};

} // namespace neuro_mesh::ai
