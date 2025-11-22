#ifndef PERFORMANCEMONITOR_HPP
#define PERFORMANCEMONITOR_HPP

#include "../common/Types.hpp"
#include <atomic>
#include <chrono>
#include <vector>
#include <mutex>

namespace compression {
namespace utils {

class PerformanceMonitor : public common::NonCopyable {
private:
    struct Sample {
        std::chrono::steady_clock::time_point timestamp;
        size_t memoryUsed;
        double cpuUsage;
    };
    
    std::vector<Sample> samples_;
    std::chrono::steady_clock::time_point startTime_;
    std::mutex samplesMutex_;
    size_t maxSamples_;
    std::atomic<size_t> peakMemoryUsage_;
    std::atomic<double> averageCPUUsage_;
    
public:
    explicit PerformanceMonitor(size_t maxSamples = 1000);
    
    void start();
    void addSample(size_t memoryUsed, double cpuUsage = 0.0);
    void stop();
    
    size_t getCurrentMemoryUsage() const;
    double getCurrentCPUUsage() const;
    size_t getPeakMemoryUsage() const { return peakMemoryUsage_; }
    double getAverageCPUUsage() const { return averageCPUUsage_; }
    std::chrono::milliseconds getTotalDuration() const;
    
    common::CompressionStats getStats() const;
    void reset();
    
private:
    double calculateCPUUsage() const;
    size_t getSystemMemoryUsage() const;
};

} 
} 

#endif