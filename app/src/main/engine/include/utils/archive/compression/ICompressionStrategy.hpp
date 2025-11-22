// include/compression/ICompressionStrategy.hpp
#ifndef ICOMPRESSIONSTRATEGY_HPP
#define ICOMPRESSIONSTRATEGY_HPP

#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include <system_error>
#include <memory>

namespace compression {
namespace compression {

class ICompressionStrategy {
public:
    virtual ~ICompressionStrategy() = default;
    
    virtual std::error_code compress(const common::ByteArray& input, 
                                   common::ByteArray& output,
                                   const common::CompressionConfig& config) = 0;
    
    virtual std::error_code decompress(const common::ByteArray& input, 
                                     common::ByteArray& output,
                                     const common::CompressionConfig& config) = 0;
    
    virtual std::error_code compressStream(const common::Byte* input, 
                                         size_t inputSize,
                                         common::Byte* output, 
                                         size_t& outputSize,
                                         const common::CompressionConfig& config) = 0;
    
    virtual std::error_code decompressStream(const common::Byte* input, 
                                           size_t inputSize,
                                           common::Byte* output, 
                                           size_t& outputSize,
                                           const common::CompressionConfig& config) = 0;
    
    virtual common::CompressionAlgorithm getAlgorithm() const = 0;
    virtual std::string getAlgorithmName() const = 0;
    virtual bool supportsStreaming() const = 0;
    virtual size_t getMaxCompressedSize(size_t inputSize) const = 0;
    virtual bool supportsLevel(int level) const = 0;
};

} // namespace compression
} // namespace compression

#endif