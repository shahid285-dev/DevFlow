#include "../../include/utils/PerformanceMonitor.hpp"
#include <fstream>
#include <sstream>
#include <thread>

compression::utils::PerformanceMonitor::PerformanceMonitor(size_t maxSamples)
    : maxSamples_(maxSamples), peakMemoryUsage_(0), averageCPUUsage_(0.0) {}

void compression::utils::PerformanceMonitor::start() {
    reset();
    startTime_ = std::chrono::steady_clock::now();
}

void compression::utils::PerformanceMonitor::addSample(size_t memoryUsed, double cpuUsage) {
    std::lock_guard<std::mutex> lock(samplesMutex_);
    
    Sample sample;
    sample.timestamp = std::chrono::steady_clock::now();
    sample.memoryUsed = memoryUsed;
    sample.cpuUsage = cpuUsage;
    
    samples_.push_back(sample);
    
    if (memoryUsed > peakMemoryUsage_.load()) {
        peakMemoryUsage_.store(memoryUsed);
    }
    
    if (samples_.size() > maxSamples_) {
        samples_.erase(samples_.begin());
    }
    
    double totalCPU = 0.0;
    for (const auto& s : samples_) {
        totalCPU += s.cpuUsage;
    }
    averageCPUUsage_.store(totalCPU / samples_.size());
}

void compression::utils::PerformanceMonitor::stop() {
    std::lock_guard<std::mutex> lock(samplesMutex_);
    samples_.clear();
}

size_t compression::utils::PerformanceMonitor::getCurrentMemoryUsage() const {
    std::ifstream statusFile("/proc/self/status");
    if (!statusFile.is_open()) {
        return 0;
    }
    
    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.find("VmRSS:") == 0) {
            std::istringstream iss(line);
            std::string key;
            size_t value;
            std::string unit;
            iss >> key >> value >> unit;
            return value * 1024;
        }
    }
    
    return 0;
}

double compression::utils::PerformanceMonitor::getCurrentCPUUsage() const {
    return calculateCPUUsage();
}

std::chrono::milliseconds compression::utils::PerformanceMonitor::getTotalDuration() const {
    auto endTime = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime_);
}

compression::common::CompressionStats compression::utils::PerformanceMonitor::getStats() const {
    compression::common::CompressionStats stats;
    
    std::lock_guard<std::mutex> lock(samplesMutex_);
    
    if (!samples_.empty()) {
        stats.memoryUsed = peakMemoryUsage_.load();
        stats.timeTakenMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            samples_.back().timestamp - startTime_).count();
    }
    
    return stats;
}

void compression::utils::PerformanceMonitor::reset() {
    std::lock_guard<std::mutex> lock(samplesMutex_);
    samples_.clear();
    peakMemoryUsage_.store(0);
    averageCPUUsage_.store(0.0);
    startTime_ = std::chrono::steady_clock::now();
}

double compression::utils::PerformanceMonitor::calculateCPUUsage() const {
    static size_t previousTotalTime = 0;
    static size_t previousIdleTime = 0;
    
    std::ifstream statFile("/proc/stat");
    if (!statFile.is_open()) {
        return 0.0;
    }
    
    std::string line;
    if (!std::getline(statFile, line)) {
        return 0.0;
    }
    
    std::istringstream iss(line);
    std::string cpu;
    size_t user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal >> guest >> guest_nice;
    
    size_t totalTime = user + nice + system + idle + iowait + irq + softirq + steal;
    size_t idleTime = idle + iowait;
    
    size_t totalTimeDiff = totalTime - previousTotalTime;
    size_t idleTimeDiff = idleTime - previousIdleTime;
    
    previousTotalTime = totalTime;
    previousIdleTime = idleTime;
    
    if (totalTimeDiff == 0) {
        return 0.0;
    }
    
    double cpuUsage = 100.0 * (1.0 - static_cast<double>(idleTimeDiff) / totalTimeDiff);
    return cpuUsage;
}

size_t compression::utils::PerformanceMonitor::getSystemMemoryUsage() const {
    std::ifstream memInfo("/proc/meminfo");
    if (!memInfo.is_open()) {
        return 0;
    }
    
    std::string line;
    size_t totalMemory = 0;
    size_t freeMemory = 0;
    size_t availableMemory = 0;
    
    while (std::getline(memInfo, line)) {
        std::istringstream iss(line);
        std::string key;
        size_t value;
        std::string unit;
        
        iss >> key >> value >> unit;
        
        if (key == "MemTotal:") {
            totalMemory = value * 1024;
        } else if (key == "MemFree:") {
            freeMemory = value * 1024;
        } else if (key == "MemAvailable:") {
            availableMemory = value * 1024;
        }
    }
    
    if (totalMemory > 0 && availableMemory > 0) {
        return totalMemory - availableMemory;
    }
    
    return 0;
}
