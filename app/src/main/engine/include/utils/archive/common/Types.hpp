// include/common/Types.hpp
#ifndef TYPES_HPP
#define TYPES_HPP

#include <cstdint>
#include <vector>
#include <memory>
#include <string>

namespace compression {
namespace common {

using Byte = uint8_t;
using ByteArray = std::vector<Byte>;
using BytePtr = std::unique_ptr<Byte[]>;
using ConstBytePtr = const Byte*;

enum class CompressionAlgorithm {
    ZLIB,
    LZ4,
    AUTO_DETECT
};

enum class CompressionLevel {
    FAST = 1,
    BALANCED = 3,
    HIGH = 6,
    MAXIMUM = 9
};

enum class ContentType {
    UNKNOWN,
    TEXT,
    JSON,
    BINARY,
    DATABASE
};

struct CompressionStats {
    size_t originalSize;
    size_t compressedSize;
    size_t memoryUsed;
    double compressionRatio;
    double timeTakenMs;
    uint32_t checksum;
    
    CompressionStats() : originalSize(0), compressedSize(0), memoryUsed(0), 
                        compressionRatio(0.0), timeTakenMs(0.0), checksum(0) {}
};

struct CompressionConfig {
    CompressionAlgorithm algorithm;
    CompressionLevel level;
    ContentType contentType;
    size_t chunkSize;
    bool enableChecksum;
    bool useAsync;
    size_t memoryLimit;
    
    CompressionConfig() : algorithm(CompressionAlgorithm::ZLIB),
                         level(CompressionLevel::BALANCED),
                         contentType(ContentType::UNKNOWN),
                         chunkSize(65536),
                         enableChecksum(true),
                         useAsync(false),
                         memoryLimit(104857600) {} // 100MB default
};

struct ProgressData {
    size_t bytesProcessed;
    size_t totalBytes;
    double percentage;
    bool completed;
    bool cancelled;
    
    ProgressData() : bytesProcessed(0), totalBytes(0), percentage(0.0),
                    completed(false), cancelled(false) {}
};

using ProgressCallback = std::function<void(const ProgressData&)>;
using CompletionCallback = std::function<void(const CompressionStats&)>;
using ErrorCallback = std::function<void(int, const std::string&)>;

class NonCopyable {
protected:
    NonCopyable() = default;
    ~NonCopyable() = default;
    
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;
    
    NonCopyable(NonCopyable&&) = default;
    NonCopyable& operator=(NonCopyable&&) = default;
};

} // namespace common
} // namespace compression

#endif