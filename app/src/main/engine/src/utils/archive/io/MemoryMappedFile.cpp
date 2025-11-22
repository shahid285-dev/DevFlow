#include "../../include/io/MemoryMappedFile.hpp"
#include "../../include/io/FileHandler.hpp"
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

compression::io::MemoryMappedFile::MemoryMappedFile(const std::string& filePath)
    : filePath_(filePath), mappedData_(nullptr), mappedSize_(0), fileSize_(0), 
      isMapped_(false), fileDescriptor_(-1) {}

compression::io::MemoryMappedFile::~MemoryMappedFile() {
    unmap();
}

std::error_code compression::io::MemoryMappedFile::openFile() {
    if (fileDescriptor_ != -1) {
        closeFile();
    }

    fileDescriptor_ = open(filePath_.c_str(), O_RDONLY);
    if (fileDescriptor_ == -1) {
        return compression::common::ErrorCode::FILE_ACCESS_DENIED;
    }

    struct stat fileStat;
    if (fstat(fileDescriptor_, &fileStat) == -1) {
        closeFile();
        return compression::common::ErrorCode::FILE_READ_ERROR;
    }

    if (fileStat.st_size == 0) {
        closeFile();
        return compression::common::ErrorCode::FILE_TOO_LARGE;
    }

    fileSize_ = static_cast<size_t>(fileStat.st_size);
    return compression::common::ErrorCode::SUCCESS;
}

void compression::io::MemoryMappedFile::closeFile() {
    if (fileDescriptor_ != -1) {
        close(fileDescriptor_);
        fileDescriptor_ = -1;
    }
}

std::error_code compression::io::MemoryMappedFile::map(size_t offset, size_t length) {
    if (isMapped_) {
        unmap();
    }

    auto openResult = openFile();
    if (openResult) {
        return openResult;
    }

    if (fileSize_ == 0) {
        closeFile();
        return compression::common::ErrorCode::FILE_TOO_LARGE;
    }

    if (offset >= fileSize_) {
        closeFile();
        return compression::common::ErrorCode::BUFFER_OVERFLOW;
    }

    if (length == 0) {
        length = fileSize_ - offset;
    } else if (offset + length > fileSize_) {
        length = fileSize_ - offset;
    }

    if (length == 0) {
        closeFile();
        return compression::common::ErrorCode::FILE_TOO_LARGE;
    }

    mappedData_ = static_cast<compression::common::Byte*>(
        mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fileDescriptor_, offset)
    );

    if (mappedData_ == MAP_FAILED) {
        mappedData_ = nullptr;
        closeFile();
        return compression::common::ErrorCode::MEMORY_ALLOCATION_FAILED;
    }

    mappedSize_ = length;
    isMapped_ = true;

    return compression::common::ErrorCode::SUCCESS;
}

void compression::io::MemoryMappedFile::unmap() {
    if (isMapped_ && mappedData_ && mappedSize_ > 0) {
        munmap(mappedData_, mappedSize_);
        mappedData_ = nullptr;
        mappedSize_ = 0;
        isMapped_ = false;
    }
    closeFile();
}

std::error_code compression::io::MemoryMappedFile::flush() {
    if (!isMapped_ || !mappedData_ || mappedSize_ == 0) {
        return compression::common::ErrorCode::SUCCESS;
    }

    if (msync(mappedData_, mappedSize_, MS_SYNC) == -1) {
        return compression::common::ErrorCode::FILE_WRITE_ERROR;
    }

    return compression::common::ErrorCode::SUCCESS;
}