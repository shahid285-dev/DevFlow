#ifndef THERMALMONITOR_HPP
#define THERMALMONITOR_HPP

#include "../common/Types.hpp"
#include "../common/Constants.hpp"
#include <atomic>
#include <mutex>
#include <vector>
#include <functional>

namespace compression {
namespace utils {

class ThermalMonitor : public common::NonCopyable {
private:
    std::atomic<double> currentTemperature_;
    std::atomic<double> temperatureThreshold_;
    std::atomic<bool> isThrottling_;
    std::vector<std::function<void(bool)>> throttleCallbacks_;
    std::mutex callbacksMutex_;
    
    
public:
    ThermalMonitor();
    explicit ThermalMonitor(double threshold);
    
    void updateTemperature(double temperature);
    void setThreshold(double threshold);
    
    double getCurrentTemperature() const { return currentTemperature_; }
    double getThreshold() const { return temperatureThreshold_; }
    bool isThrottling() const { return isThrottling_; }
    
    double getThrottleLevel() const;
    common::CompressionLevel getSafeCompressionLevel() const;
    size_t getSafeChunkSize() const;
    bool shouldReduceThreadCount() const;
    
    void registerThrottleCallback(std::function<void(bool)> callback);
    void unregisterAllCallbacks();
    
    static ThermalMonitor& getInstance();
    
private:
    void checkThrottleState();
    void notifyThrottleCallbacks(bool throttling);
};

}
}

#endif