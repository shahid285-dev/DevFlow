// include/compression/CompressionResult.hpp
#ifndef COMPRESSIONRESULT_HPP
#define COMPRESSIONRESULT_HPP

#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include <system_error>
#include <chrono>

namespace compression {
namespace compression {

class CompressionResult {
private:
    std::error_code error_;
    common::CompressionStats stats_;
    common::CompressionConfig config_;
    std::chrono::steady_clock::time_point startTime_;
    std::chrono::steady_clock::time_point endTime_;
    
public:
    CompressionResult();
    explicit CompressionResult(std::error_code error);
    CompressionResult(std::error_code error, const common::CompressionStats& stats);
    
    void startTimer();
    void stopTimer();
    
    void setError(std::error_code error) { error_ = error; }
    void setStats(const common::CompressionStats& stats) { stats_ = stats; }
    void setConfig(const common::CompressionConfig& config) { config_ = config; }
    
    std::error_code getError() const { return error_; }
    const common::CompressionStats& getStats() const { return stats_; }
    const common::CompressionConfig& getConfig() const { return config_; }
    
    bool success() const { return !error_; }
    bool failed() const { return !!error_; }
    
    double getCompressionRatio() const { return stats_.compressionRatio; }
    size_t getOriginalSize() const { return stats_.originalSize; }
    size_t getCompressedSize() const { return stats_.compressedSize; }
    double getTimeTakenMs() const { return stats_.timeTakenMs; }
    
    std::string getErrorString() const;
    
    static CompressionResult successResult(const common::CompressionStats& stats);
    static CompressionResult errorResult(std::error_code error);
    static CompressionResult errorResult(common::ErrorCode error);
};

} // namespace compression
} // namespace compression

#endif