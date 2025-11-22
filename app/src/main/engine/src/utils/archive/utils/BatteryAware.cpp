#include "../../include/utils/BatteryAware.hpp"

compression::utils::BatteryAware::BatteryAware()
    : batteryLevel_(1.0), powerConnected_(false), lowPowerMode_(false) {}

void compression::utils::BatteryAware::updateBatteryLevel(double level) {
    if (level >= 0.0 && level <= 1.0) {
        batteryLevel_.store(level);
    }
}

void compression::utils::BatteryAware::setPowerConnected(bool connected) {
    powerConnected_.store(connected);
}

void compression::utils::BatteryAware::setLowPowerMode(bool enabled) {
    lowPowerMode_.store(enabled);
}

bool compression::utils::BatteryAware::isBatteryLow() const {
    return batteryLevel_.load() < compression::common::Constants::BATTERY_SAVE_THRESHOLD;
}

compression::common::CompressionLevel compression::utils::BatteryAware::getRecommendedCompressionLevel() const {
    double batteryLevel = batteryLevel_.load();
    bool powerConnected = powerConnected_.load();
    bool lowPowerMode = lowPowerMode_.load();
    
    if (lowPowerMode || (batteryLevel < 0.1 && !powerConnected)) {
        return compression::common::CompressionLevel::FAST;
    } else if (batteryLevel < 0.3 && !powerConnected) {
        return compression::common::CompressionLevel::BALANCED;
    } else if (batteryLevel < compression::common::Constants::BATTERY_SAVE_THRESHOLD && !powerConnected) {
        return compression::common::CompressionLevel::BALANCED;
    } else if (powerConnected) {
        return compression::common::CompressionLevel::HIGH;
    } else {
        return compression::common::CompressionLevel::BALANCED;
    }
}

bool compression::utils::BatteryAware::shouldUseFastAlgorithm() const {
    double batteryLevel = batteryLevel_.load();
    bool powerConnected = powerConnected_.load();
    bool lowPowerMode = lowPowerMode_.load();
    
    return lowPowerMode || (batteryLevel < 0.2 && !powerConnected);
}

size_t compression::utils::BatteryAware::getRecommendedChunkSize() const {
    double batteryLevel = batteryLevel_.load();
    bool powerConnected = powerConnected_.load();
    bool lowPowerMode = lowPowerMode_.load();
    
    if (lowPowerMode || (batteryLevel < 0.15 && !powerConnected)) {
        return compression::common::Constants::MIN_CHUNK_SIZE;
    } else if (batteryLevel < 0.3 && !powerConnected) {
        return compression::common::Constants::DEFAULT_CHUNK_SIZE / 2;
    } else if (batteryLevel < compression::common::Constants::BATTERY_SAVE_THRESHOLD && !powerConnected) {
        return compression::common::Constants::DEFAULT_CHUNK_SIZE;
    } else {
        return compression::common::Constants::DEFAULT_CHUNK_SIZE;
    }
}

bool compression::utils::BatteryAware::shouldCompressInBackground() const {
    double batteryLevel = batteryLevel_.load();
    bool powerConnected = powerConnected_.load();
    
    return powerConnected || batteryLevel > 0.5;
}

compression::utils::BatteryAware& compression::utils::BatteryAware::getInstance() {
    static BatteryAware instance;
    return instance;
}
