#include "../../include/utils/archive/ProgressTracker.hpp"

compression::utils::ProgressTracker::ProgressTracker(size_t updateInterval)
    : bytesProcessed_(0), totalBytes_(0), cancelled_(false), completed_(false),
      updateInterval_(updateInterval), lastReportedBytes_(0) {
    startTime_ = std::chrono::steady_clock::now();
}

compression::utils::ProgressTracker::~ProgressTracker() {
    if (!completed_ && !cancelled_) {
        setCompleted();
    }
}

void compression::utils::ProgressTracker::setTotalBytes(size_t total) {
    totalBytes_.store(total);
    update();
}

void compression::utils::ProgressTracker::addProcessedBytes(size_t bytes) {
    if (cancelled_.load() || completed_.load()) {
        return;
    }
    
    bytesProcessed_.fetch_add(bytes);
    
    size_t currentBytes = bytesProcessed_.load();
    if (currentBytes - lastReportedBytes_ >= updateInterval_ || currentBytes == totalBytes_.load()) {
        update();
        lastReportedBytes_ = currentBytes;
    }
}

void compression::utils::ProgressTracker::setCompleted() {
    completed_.store(true);
    update();
}

void compression::utils::ProgressTracker::cancel() {
    cancelled_.store(true);
    update();
}

double compression::utils::ProgressTracker::getPercentage() const {
    size_t total = totalBytes_.load();
    if (total == 0) {
        return 0.0;
    }
    
    size_t processed = bytesProcessed_.load();
    return (static_cast<double>(processed) / static_cast<double>(total)) * 100.0;
}

double compression::utils::ProgressTracker::getSpeedBytesPerSecond() const {
    auto elapsed = getElapsedTime();
    if (elapsed.count() == 0) {
        return 0.0;
    }
    
    size_t processed = bytesProcessed_.load();
    return static_cast<double>(processed) / (elapsed.count() / 1000.0);
}

std::chrono::milliseconds compression::utils::ProgressTracker::getElapsedTime() const {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime_);
}

void compression::utils::ProgressTracker::setProgressCallback(compression::common::ProgressCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    progressCallback_ = callback;
}

void compression::utils::ProgressTracker::update() {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    
    if (progressCallback_) {
        compression::common::ProgressData data;
        data.bytesProcessed = bytesProcessed_.load();
        data.totalBytes = totalBytes_.load();
        data.percentage = getPercentage();
        data.completed = completed_.load();
        data.cancelled = cancelled_.load();
        
        progressCallback_(data);
    }
}

void compression::utils::ProgressTracker::reset() {
    bytesProcessed_.store(0);
    totalBytes_.store(0);
    cancelled_.store(false);
    completed_.store(false);
    lastReportedBytes_ = 0;
    startTime_ = std::chrono::steady_clock::now();
    update();
}