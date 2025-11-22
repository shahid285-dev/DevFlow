#ifndef BATTERYAWARE_HPP
#define BATTERYAWARE_HPP

#include "../common/Types.hpp"
#include "../common/Constants.hpp"
#include <atomic>

namespace compression {
namespace utils {

class BatteryAware : public common::NonCopyable {
private:
    std::atomic<double> batteryLevel_;
    std::atomic<bool> powerConnected_;
    std::atomic<bool> lowPowerMode_;
    
public:
    BatteryAware();
    
    void updateBatteryLevel(double level);
    void setPowerConnected(bool connected);
    void setLowPowerMode(bool enabled);
    
    double getBatteryLevel() const { return batteryLevel_; }
    bool isPowerConnected() const { return powerConnected_; }
    bool isLowPowerMode() const { return lowPowerMode_; }
    bool isBatteryLow() const;
    
    common::CompressionLevel getRecommendedCompressionLevel() const;
    bool shouldUseFastAlgorithm() const;
    size_t getRecommendedChunkSize() const;
    bool shouldCompressInBackground() const;
    
    static BatteryAware& getInstance();
};

} 
}

#endif