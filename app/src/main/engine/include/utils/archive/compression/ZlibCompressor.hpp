// include/compression/ZlibCompressor.hpp
#ifndef ZLIBCOMPRESSOR_HPP
#define ZLIBCOMPRESSOR_HPP

#include "ICompressionStrategy.hpp"
#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include <memory>

namespace compression {
namespace compression {

class ZlibCompressor : public ICompressionStrategy {
private:
    struct ZlibContext;
    std::unique_ptr<ZlibContext> context_;
    
public:
    ZlibCompressor();
    ~ZlibCompressor();
    
    std::error_code compress(const common::ByteArray& input, 
                           common::ByteArray& output,
                           const common::CompressionConfig& config) override;
    
    std::error_code decompress(const common::ByteArray& input, 
                             common::ByteArray& output,
                             const common::CompressionConfig& config) override;
    
    std::error_code compressStream(const common::Byte* input, 
                                 size_t inputSize,
                                 common::Byte* output, 
                                 size_t& outputSize,
                                 const common::CompressionConfig& config) override;
    
    std::error_code decompressStream(const common::Byte* input, 
                                   size_t inputSize,
                                   common::Byte* output, 
                                   size_t& outputSize,
                                   const common::CompressionConfig& config) override;
    
    common::CompressionAlgorithm getAlgorithm() const override { 
        return common::CompressionAlgorithm::ZLIB; 
    }
    
    std::string getAlgorithmName() const override { return "ZLIB"; }
    
    bool supportsStreaming() const override { return true; }
    
    size_t getMaxCompressedSize(size_t inputSize) const override;
    
    bool supportsLevel(int level) const override {
        return level >= 0 && level <= 9;
    }
    
private:
    std::error_code initializeCompression(const common::CompressionConfig& config);
    std::error_code initializeDecompression();
    void cleanup();
};

} // namespace compression
} // namespace compression

#endif