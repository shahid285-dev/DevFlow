// include/compression/AsyncCompressor.hpp
#ifndef ASYNCCOMPRESSOR_HPP
#define ASYNCCOMPRESSOR_HPP

#include "ICompressionStrategy.hpp"
#include "../common/Types.hpp"
#include "../utils/ThreadPool.hpp"
#include <future>
#include <memory>

namespace compression {
namespace compression {

class AsyncCompressor : public common::NonCopyable {
private:
    std::unique_ptr<ICompressionStrategy> compressor_;
    std::shared_ptr<utils::ThreadPool> threadPool_;
    
public:
    explicit AsyncCompressor(std::unique_ptr<ICompressionStrategy> compressor,
                           std::shared_ptr<utils::ThreadPool> pool = nullptr);
    
    std::future<CompressionResult> compressAsync(const common::ByteArray& input,
                                               const common::CompressionConfig& config,
                                               common::ProgressCallback progressCallback = nullptr);
    
    std::future<CompressionResult> decompressAsync(const common::ByteArray& input,
                                                 const common::CompressionConfig& config,
                                                 common::ProgressCallback progressCallback = nullptr);
    
    std::future<CompressionResult> compressFileAsync(const std::string& inputPath,
                                                   const std::string& outputPath,
                                                   const common::CompressionConfig& config,
                                                   common::ProgressCallback progressCallback = nullptr);
    
    std::future<CompressionResult> decompressFileAsync(const std::string& inputPath,
                                                     const std::string& outputPath,
                                                     const common::CompressionConfig& config,
                                                     common::ProgressCallback progressCallback = nullptr);
    
    void cancelAll();
    
    common::CompressionAlgorithm getAlgorithm() const;
    std::string getAlgorithmName() const;
    
private:
    CompressionResult compressInternal(const common::ByteArray& input,
                                     const common::CompressionConfig& config,
                                     common::ProgressCallback progressCallback);
    
    CompressionResult decompressInternal(const common::ByteArray& input,
                                       const common::CompressionConfig& config,
                                       common::ProgressCallback progressCallback);
};

} // namespace compression
} // namespace compression

#endif