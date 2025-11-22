// include/compression/StreamProcessor.hpp
#ifndef STREAMPROCESSOR_HPP
#define STREAMPROCESSOR_HPP

#include "ICompressionStrategy.hpp"
#include "../common/Types.hpp"
#include "../io/StreamWrapper.hpp"
#include <memory>

namespace compression {
namespace compression {

class StreamProcessor : public common::NonCopyable {
private:
    std::unique_ptr<ICompressionStrategy> compressor_;
    common::CompressionConfig config_;
    size_t chunkSize_;
    
public:
    StreamProcessor(std::unique_ptr<ICompressionStrategy> compressor,
                   const common::CompressionConfig& config);
    
    std::error_code compressStream(std::unique_ptr<io::IStream> input,
                                 std::unique_ptr<io::IStream> output,
                                 common::ProgressCallback progressCallback = nullptr);
    
    std::error_code decompressStream(std::unique_ptr<io::IStream> input,
                                   std::unique_ptr<io::IStream> output,
                                   common::ProgressCallback progressCallback = nullptr);
    
    void setChunkSize(size_t chunkSize) { chunkSize_ = chunkSize; }
    size_t getChunkSize() const { return chunkSize_; }
    
    common::CompressionAlgorithm getAlgorithm() const;
    
private:
    std::error_code processStream(std::unique_ptr<io::IStream> input,
                                std::unique_ptr<io::IStream> output,
                                bool compress,
                                common::ProgressCallback progressCallback);
};

} // namespace compression
} // namespace compression

#endif