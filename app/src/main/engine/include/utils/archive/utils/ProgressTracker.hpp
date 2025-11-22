// include/utils/ProgressTracker.hpp
#ifndef PROGRESSTRACKER_HPP
#define PROGRESSTRACKER_HPP

#include "../common/Types.hpp"
#include <atomic>
#include <functional>
#include <mutex>
#include <chrono>

namespace compression {
namespace utils {

class ProgressTracker : public common::NonCopyable {
private:
    std::atomic<size_t> bytesProcessed_;
    std::atomic<size_t> totalBytes_;
    std::atomic<bool> cancelled_;
    std::atomic<bool> completed_;
    std::chrono::steady_clock::time_point startTime_;
    common::ProgressCallback progressCallback_;
    std::mutex callbackMutex_;
    size_t updateInterval_;
    size_t lastReportedBytes_;
    
public:
    explicit ProgressTracker(size_t updateInterval = 1024); // Update every 1KB by default
    ~ProgressTracker();
    
    void setTotalBytes(size_t total);
    void addProcessedBytes(size_t bytes);
    void setCompleted();
    void cancel();
    
    bool isCancelled() const { return cancelled_; }
    bool isCompleted() const { return completed_; }
    size_t getBytesProcessed() const { return bytesProcessed_; }
    size_t getTotalBytes() const { return totalBytes_; }
    double getPercentage() const;
    double getSpeedBytesPerSecond() const;
    std::chrono::milliseconds getElapsedTime() const;
    
    void setProgressCallback(common::ProgressCallback callback);
    void update();
    
    void reset();
};

} // namespace utils
} // namespace compression

#endif