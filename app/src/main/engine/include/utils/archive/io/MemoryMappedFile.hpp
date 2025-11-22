#ifndef MEMORYMAPPEDFILE_HPP
#define MEMORYMAPPEDFILE_HPP

#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include <string>
#include <system_error>

namespace compression {
namespace io {

class MemoryMappedFile : public common::NonCopyable {
private:
    std::string filePath_;
    common::Byte* mappedData_;
    size_t mappedSize_;
    size_t fileSize_;
    bool isMapped_;
    
#ifdef _WIN32
    void* fileHandle_;
    void* mappingHandle_;
#else
    int fileDescriptor_;
#endif

public:
    explicit MemoryMappedFile(const std::string& filePath);
    ~MemoryMappedFile();
    
    std::error_code map(size_t offset = 0, size_t length = 0);
    void unmap();
    
    bool isMapped() const { return isMapped_; }
    const common::Byte* getData() const { return mappedData_; }
    common::Byte* getData() { return mappedData_; }
    size_t getSize() const { return mappedSize_; }
    size_t getFileSize() const { return fileSize_; }
    std::string getFilePath() const { return filePath_; }
    
    std::error_code flush();
    
private:
    std::error_code openFile();
    void closeFile();
};

} 
} 

#endif