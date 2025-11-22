// include/compression/LZ4Compressor.hpp
#ifndef LZ4COMPRESSOR_HPP
#define LZ4COMPRESSOR_HPP

#include "ICompressionStrategy.hpp"
#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include <memory>

namespace compression {
namespace compression {

class LZ4Compressor : public ICompressionStrategy {
private:
    struct LZ4Context;
    std::unique_ptr<LZ4Context> context_;
    
public:
    LZ4Compressor();
    ~LZ4Compressor();
    
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
        return common::CompressionAlgorithm::LZ4; 
    }
    
    std::string getAlgorithmName() const override { return "LZ4"; }
    
    bool supportsStreaming() const override { return true; }
    
    size_t getMaxCompressedSize(size_t inputSize) const override;
    
    bool supportsLevel(int level) const override {
        return level >= 0 && level <= 12;
    }
    
private:
    std::error_code initializeCompression(const common::CompressionConfig& config);
    std::error_code initializeDecompression();
    void cleanup();
};

} // namespace compression
} // namespace compression

#endif