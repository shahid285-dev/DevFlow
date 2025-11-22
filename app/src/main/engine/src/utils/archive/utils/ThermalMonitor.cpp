#include "../../include/utils/ThermalMonitor.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>
#include <string>
#include <dirent.h>

compression::utils::ThermalMonitor::ThermalMonitor()
    : currentTemperature_(25.0), temperatureThreshold_(compression::common::Constants::THERMAL_THROTTLE_THRESHOLD),
      isThrottling_(false) {
    updateTemperatureFromSystem();
}

compression::utils::ThermalMonitor::ThermalMonitor(double threshold)
    : currentTemperature_(25.0), temperatureThreshold_(threshold), isThrottling_(false) {
    updateTemperatureFromSystem();
}

void compression::utils::ThermalMonitor::updateTemperature(double temperature) {
    if (temperature >= -50.0 && temperature <= 150.0) {
        currentTemperature_.store(temperature);
        checkThrottleState();
    }
}

void compression::utils::ThermalMonitor::setThreshold(double threshold) {
    if (threshold > 0.0 && threshold <= 100.0) {
        temperatureThreshold_.store(threshold);
        checkThrottleState();
    }
}

double compression::utils::ThermalMonitor::getThrottleLevel() const {
    double currentTemp = currentTemperature_.load();
    double threshold = temperatureThreshold_.load();
    
    if (currentTemp <= threshold) {
        return 0.0;
    }
    
    double excess = currentTemp - threshold;
    double maxExcess = 30.0;
    
    return std::min(excess / maxExcess, 1.0);
}

compression::common::CompressionLevel compression::utils::ThermalMonitor::getSafeCompressionLevel() const {
    double throttleLevel = getThrottleLevel();
    
    if (throttleLevel > 0.7) {
        return compression::common::CompressionLevel::FAST;
    } else if (throttleLevel > 0.5) {
        return compression::common::CompressionLevel::BALANCED;
    } else if (throttleLevel > 0.3) {
        return compression::common::CompressionLevel::HIGH;
    } else {
        return compression::common::CompressionLevel::MAXIMUM;
    }
}

size_t compression::utils::ThermalMonitor::getSafeChunkSize() const {
    double throttleLevel = getThrottleLevel();
    size_t defaultChunkSize = compression::common::Constants::DEFAULT_CHUNK_SIZE;
    
    if (throttleLevel > 0.7) {
        return compression::common::Constants::MIN_CHUNK_SIZE;
    } else if (throttleLevel > 0.5) {
        return defaultChunkSize / 4;
    } else if (throttleLevel > 0.3) {
        return defaultChunkSize / 2;
    } else {
        return defaultChunkSize;
    }
}

bool compression::utils::ThermalMonitor::shouldReduceThreadCount() const {
    double throttleLevel = getThrottleLevel();
    return throttleLevel > 0.4;
}

void compression::utils::ThermalMonitor::registerThrottleCallback(std::function<void(bool)> callback) {
    std::lock_guard<std::mutex> lock(callbacksMutex_);
    throttleCallbacks_.push_back(callback);
}

void compression::utils::ThermalMonitor::unregisterAllCallbacks() {
    std::lock_guard<std::mutex> lock(callbacksMutex_);
    throttleCallbacks_.clear();
}

compression::utils::ThermalMonitor& compression::utils::ThermalMonitor::getInstance() {
    static ThermalMonitor instance;
    return instance;
}

void compression::utils::ThermalMonitor::checkThrottleState() {
    double currentTemp = currentTemperature_.load();
    double threshold = temperatureThreshold_.load();
    bool wasThrottling = isThrottling_.load();
    bool nowThrottling = currentTemp > threshold;
    
    if (wasThrottling != nowThrottling) {
        isThrottling_.store(nowThrottling);
        notifyThrottleCallbacks(nowThrottling);
    }
}

void compression::utils::ThermalMonitor::notifyThrottleCallbacks(bool throttling) {
    std::lock_guard<std::mutex> lock(callbacksMutex_);
    
    for (const auto& callback : throttleCallbacks_) {
        if (callback) {
            callback(throttling);
        }
    }
}

double compression::utils::ThermalMonitor::updateTemperatureFromSystem() {
    std::vector<std::string> thermalZones = findThermalZones();
    double maxTemperature = 0.0;
    int validReadings = 0;
    
    for (const auto& zone : thermalZones) {
        double temp = readThermalZoneTemperature(zone);
        if (temp > 0.0) {
            maxTemperature = std::max(maxTemperature, temp);
            validReadings++;
        }
    }
    
    if (validReadings > 0) {
        updateTemperature(maxTemperature);
        return maxTemperature;
    }
    
    return readFallbackTemperature();
}

std::vector<std::string> compression::utils::ThermalMonitor::findThermalZones() {
    std::vector<std::string> thermalZones;
    const std::string thermalBasePath = "/sys/class/thermal";
    
    DIR* dir = opendir(thermalBasePath.c_str());
    if (!dir) {
        return thermalZones;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name.find("thermal_zone") == 0) {
            thermalZones.push_back(thermalBasePath + "/" + name);
        }
    }
    closedir(dir);
    
    return thermalZones;
}

double compression::utils::ThermalMonitor::readThermalZoneTemperature(const std::string& zonePath) {
    std::string tempFile = zonePath + "/temp";
    std::ifstream file(tempFile);
    
    if (!file.is_open()) {
        return 0.0;
    }
    
    std::string line;
    if (std::getline(file, line)) {
        try {
            long millidegrees = std::stol(line);
            return static_cast<double>(millidegrees) / 1000.0;
        } catch (const std::exception&) {
            return 0.0;
        }
    }
    
    return 0.0;
}

double compression::utils::ThermalMonitor::readFallbackTemperature() {
    std::vector<std::string> fallbackPaths = {
        "/sys/class/hwmon/hwmon0/temp1_input",
        "/sys/class/hwmon/hwmon1/temp1_input",
        "/sys/devices/virtual/thermal/thermal_zone0/temp"
    };
    
    for (const auto& path : fallbackPaths) {
        std::ifstream file(path);
        if (file.is_open()) {
            std::string line;
            if (std::getline(file, line)) {
                try {
                    long millidegrees = std::stol(line);
                    double temperature = static_cast<double>(millidegrees) / 1000.0;
                    if (temperature > 0.0 && temperature < 150.0) {
                        updateTemperature(temperature);
                        return temperature;
                    }
                } catch (const std::exception&) {
                    continue;
                }
            }
        }
    }
    
    return 25.0;
}
