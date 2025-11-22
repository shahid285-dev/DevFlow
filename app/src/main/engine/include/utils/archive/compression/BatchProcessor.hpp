// include/compression/BatchProcessor.hpp
#ifndef BATCHPROCESSOR_HPP
#define BATCHPROCESSOR_HPP

#include "ICompressionStrategy.hpp"
#include "../common/Types.hpp"
#include "../utils/ThreadPool.hpp"
#include <vector>
#include <future>
#include <memory>

namespace compression {
namespace compression {

struct BatchItem {
    std::string inputPath;
    std::string outputPath;
    common::CompressionConfig config;
    common::ProgressCallback progressCallback;
    common::CompletionCallback completionCallback;
    common::ErrorCallback errorCallback;
};

class BatchProcessor : public common::NonCopyable {
private:
    std::unique_ptr<ICompressionStrategy> compressor_;
    std::shared_ptr<utils::ThreadPool> threadPool_;
    std::atomic<size_t> completedItems_;
    std::atomic<size_t> failedItems_;
    std::atomic<bool> cancelled_;
    
public:
    explicit BatchProcessor(std::unique_ptr<ICompressionStrategy> compressor,
                          std::shared_ptr<utils::ThreadPool> pool = nullptr);
    ~BatchProcessor();
    
    void addItem(const BatchItem& item);
    void addItems(const std::vector<BatchItem>& items);
    
    std::future<common::CompressionStats> processAll();
    void processAllAsync(common::CompletionCallback completionCallback = nullptr,
                        common::ProgressCallback progressCallback = nullptr);
    
    void cancel();
    void clear();
    
    size_t getPendingCount() const;
    size_t getCompletedCount() const { return completedItems_; }
    size_t getFailedCount() const { return failedItems_; }
    bool isProcessing() const;
    bool isCancelled() const { return cancelled_; }
    
    common::CompressionAlgorithm getAlgorithm() const;
    
private:
    void processItem(const BatchItem& item);
    common::CompressionStats processAllInternal();
};

} // namespace compression
} // namespace compression

#endif