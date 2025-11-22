// include/common/ErrorCodes.hpp
#ifndef ERRORCODES_HPP
#define ERRORCODES_HPP

#include <string>
#include <system_error>

namespace compression {
namespace common {

enum class ErrorCode {
    SUCCESS = 0,
    
    // File operations
    FILE_NOT_FOUND = 100,
    FILE_ACCESS_DENIED,
    FILE_TOO_LARGE,
    FILE_READ_ERROR,
    FILE_WRITE_ERROR,
    FILE_CORRUPT,
    
    // Memory operations
    MEMORY_ALLOCATION_FAILED = 200,
    MEMORY_LIMIT_EXCEEDED,
    BUFFER_OVERFLOW,
    BUFFER_UNDERFLOW,
    
    // Compression operations
    COMPRESSION_FAILED = 300,
    DECOMPRESSION_FAILED,
    UNSUPPORTED_ALGORITHM,
    INVALID_COMPRESSION_LEVEL,
    CORRUPT_COMPRESSED_DATA,
    CHECKSUM_MISMATCH,
    
    // Stream operations
    STREAM_ERROR = 400,
    STREAM_END_UNEXPECTED,
    STREAM_BUFFER_FULL,
    
    // System operations
    SYSTEM_RESOURCE_UNAVAILABLE = 500,
    BATTERY_TOO_LOW,
    THERMAL_THROTTLING,
    OPERATION_CANCELLED,
    
    // Configuration errors
    INVALID_CONFIGURATION = 600,
    UNSUPPORTED_FEATURE,
    
    // Unknown error
    UNKNOWN_ERROR = 999
};

class CompressionErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override {
        return "compression";
    }
    
    std::string message(int ev) const override {
        switch (static_cast<ErrorCode>(ev)) {
            case ErrorCode::SUCCESS:
                return "Success";
                
            case ErrorCode::FILE_NOT_FOUND:
                return "File not found";
            case ErrorCode::FILE_ACCESS_DENIED:
                return "File access denied";
            case ErrorCode::FILE_TOO_LARGE:
                return "File too large";
            case ErrorCode::FILE_READ_ERROR:
                return "File read error";
            case ErrorCode::FILE_WRITE_ERROR:
                return "File write error";
            case ErrorCode::FILE_CORRUPT:
                return "File is corrupt";
                
            case ErrorCode::MEMORY_ALLOCATION_FAILED:
                return "Memory allocation failed";
            case ErrorCode::MEMORY_LIMIT_EXCEEDED:
                return "Memory limit exceeded";
            case ErrorCode::BUFFER_OVERFLOW:
                return "Buffer overflow";
            case ErrorCode::BUFFER_UNDERFLOW:
                return "Buffer underflow";
                
            case ErrorCode::COMPRESSION_FAILED:
                return "Compression failed";
            case ErrorCode::DECOMPRESSION_FAILED:
                return "Decompression failed";
            case ErrorCode::UNSUPPORTED_ALGORITHM:
                return "Unsupported compression algorithm";
            case ErrorCode::INVALID_COMPRESSION_LEVEL:
                return "Invalid compression level";
            case ErrorCode::CORRUPT_COMPRESSED_DATA:
                return "Corrupt compressed data";
            case ErrorCode::CHECKSUM_MISMATCH:
                return "Checksum mismatch";
                
            case ErrorCode::STREAM_ERROR:
                return "Stream error";
            case ErrorCode::STREAM_END_UNEXPECTED:
                return "Unexpected end of stream";
            case ErrorCode::STREAM_BUFFER_FULL:
                return "Stream buffer full";
                
            case ErrorCode::SYSTEM_RESOURCE_UNAVAILABLE:
                return "System resource unavailable";
            case ErrorCode::BATTERY_TOO_LOW:
                return "Battery too low for operation";
            case ErrorCode::THERMAL_THROTTLING:
                return "Operation throttled due to thermal limits";
            case ErrorCode::OPERATION_CANCELLED:
                return "Operation cancelled";
                
            case ErrorCode::INVALID_CONFIGURATION:
                return "Invalid configuration";
            case ErrorCode::UNSUPPORTED_FEATURE:
                return "Unsupported feature";
                
            case ErrorCode::UNKNOWN_ERROR:
            default:
                return "Unknown error";
        }
    }
};

inline const std::error_category& compression_error_category() {
    static CompressionErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(ErrorCode e) {
    return std::error_code(static_cast<int>(e), compression_error_category());
}

inline std::error_condition make_error_condition(ErrorCode e) {
    return std::error_condition(static_cast<int>(e), compression_error_category());
}

} // namespace common
} // namespace compression

namespace std {
    template<>
    struct is_error_code_enum<compression::common::ErrorCode> : true_type {};
}

#endif