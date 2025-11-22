// include/common/Constants.hpp
#ifndef CONSTANTS_HPP
#define CONSTANTS_HPP

#include <cstddef>

namespace compression {
namespace common {

class Constants {
public:
    static constexpr size_t DEFAULT_CHUNK_SIZE = 65536;
    static constexpr size_t MAX_CHUNK_SIZE = 1048576;
    static constexpr size_t MIN_CHUNK_SIZE = 1024;
    
    static constexpr size_t MEMORY_POOL_SIZE = 10;
    static constexpr size_t MAX_MEMORY_USAGE = 268435456;
    
    static constexpr size_t LZ4_HEADER_SIZE = 15;
    static constexpr size_t ZLIB_HEADER_SIZE = 2;
    static constexpr size_t GZIP_HEADER_SIZE = 10;
    
    static constexpr int DEFAULT_ZLIB_LEVEL = 6;
    static constexpr int DEFAULT_LZ4_LEVEL = 1;
    
    static constexpr size_t STREAM_BUFFER_SIZE = 8192;
    static constexpr size_t MAX_STREAM_SIZE = 1073741824;
    
    static constexpr double BATTERY_SAVE_THRESHOLD = 0.2;
    static constexpr double THERMAL_THROTTLE_THRESHOLD = 0.8;
    
    static constexpr int MAX_THREAD_POOL_SIZE = 4;
    static constexpr int MIN_THREAD_POOL_SIZE = 1;
    
    static constexpr size_t CACHE_LINE_SIZE = 64;
    
    static const char* MAGIC_ZLIB;
    static const char* MAGIC_LZ4;
    static const char* MAGIC_GZIP;
    
    static const char* CONTENT_TYPE_TEXT;
    static const char* CONTENT_TYPE_JSON;
    static const char* CONTENT_TYPE_BINARY;
    static const char* CONTENT_TYPE_DATABASE;
};

} // namespace common
} // namespace compression

#endif