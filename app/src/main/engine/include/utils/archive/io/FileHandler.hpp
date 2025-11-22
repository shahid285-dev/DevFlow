// include/io/FileHandler.hpp
#ifndef FILEHANDLER_HPP
#define FILEHANDLER_HPP

#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include <string>
#include <system_error>
#include <memory>

namespace compression {
namespace io {

class FileHandler : public common::NonCopyable {
private:
    std::string filePath_;
    size_t fileSize_;
    bool isOpen_;
    FILE* fileHandle_;
    
public:
    explicit FileHandler(const std::string& filePath);
    ~FileHandler();
    
    std::error_code openForRead();
    std::error_code openForWrite();
    std::error_code openForAppend();
    
    void close();
    bool isOpen() const { return isOpen_; }
    size_t getFileSize() const { return fileSize_; }
    std::string getFilePath() const { return filePath_; }
    
    std::error_code read(common::ByteArray& buffer, size_t bytesToRead);
    std::error_code readAt(common::ByteArray& buffer, size_t bytesToRead, size_t offset);
    std::error_code write(const common::ByteArray& buffer);
    std::error_code write(const common::Byte* data, size_t size);
    
    std::error_code seek(size_t position);
    size_t tell() const;
    bool endOfFile() const;
    
    static bool fileExists(const std::string& filePath);
    static std::error_code getFileSize(const std::string& filePath, size_t& size);
    static std::error_code deleteFile(const std::string& filePath);
    static std::error_code renameFile(const std::string& oldPath, const std::string& newPath);
    
private:
    std::error_code updateFileSize();
};

} // namespace io
} // namespace compression

#endif