// src/io/FileHandler.cpp
#include "../../include/io/FileHandler.hpp"
#include "../../include/tools/file_engine.hpp"
#include <cstdio>

compression::io::FileHandler::FileHandler(const std::string& filePath)
    : filePath_(filePath), fileSize_(0), isOpen_(false), fileHandle_(nullptr) {}

compression::io::FileHandler::~FileHandler() {
    close();
}

std::error_code compression::io::FileHandler::openForRead() {
    if (isOpen_) {
        close();
    }

    FileEngine fileEngine;
    FILE* file = nullptr;
    if (!fileEngine.openFile(filePath_, OpenMode::Read, file)) {
        return compression::common::ErrorCode::FILE_READ_ERROR;
    }

    fileHandle_ = file;
    isOpen_ = true;
    
    auto sizeResult = updateFileSize();
    if (sizeResult) {
        return sizeResult;
    }

    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::FileHandler::openForWrite() {
    if (isOpen_) {
        close();
    }

    FileEngine fileEngine;
    if (!fileEngine.createFile(filePath_)) {
        return compression::common::ErrorCode::FILE_WRITE_ERROR;
    }

    FILE* file = nullptr;
    if (!fileEngine.openFile(filePath_, OpenMode::Write, file)) {
        return compression::common::ErrorCode::FILE_WRITE_ERROR;
    }

    fileHandle_ = file;
    isOpen_ = true;
    fileSize_ = 0;

    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::FileHandler::openForAppend() {
    if (isOpen_) {
        close();
    }

    FileEngine fileEngine;
    FILE* file = nullptr;
    if (!fileEngine.openFile(filePath_, OpenMode::Append, file)) {
        return compression::common::ErrorCode::FILE_WRITE_ERROR;
    }

    fileHandle_ = file;
    isOpen_ = true;
    
    auto sizeResult = updateFileSize();
    if (sizeResult) {
        return sizeResult;
    }

    return compression::common::ErrorCode::SUCCESS;
}

void compression::io::FileHandler::close() {
    if (fileHandle_) {
        FileEngine fileEngine;
        fileEngine.closeFile(fileHandle_);
        fileHandle_ = nullptr;
    }
    isOpen_ = false;
}

std::error_code compression::io::FileHandler::read(compression::common::ByteArray& buffer, size_t bytesToRead) {
    if (!isOpen_ || !fileHandle_) {
        return compression::common::ErrorCode::FILE_READ_ERROR;
    }

    buffer.resize(bytesToRead);
    size_t bytesRead = fread(buffer.data(), 1, bytesToRead, fileHandle_);
    
    if (bytesRead < bytesToRead) {
        if (feof(fileHandle_)) {
            buffer.resize(bytesRead);
            return compression::common::ErrorCode::SUCCESS;
        } else {
            return compression::common::ErrorCode::FILE_READ_ERROR;
        }
    }

    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::FileHandler::readAt(compression::common::ByteArray& buffer, size_t bytesToRead, size_t offset) {
    if (!isOpen_ || !fileHandle_) {
        return compression::common::ErrorCode::FILE_READ_ERROR;
    }

    if (fseek(fileHandle_, offset, SEEK_SET) != 0) {
        return compression::common::ErrorCode::FILE_READ_ERROR;
    }

    return read(buffer, bytesToRead);
}

std::error_code compression::io::FileHandler::write(const compression::common::ByteArray& buffer) {
    return write(buffer.data(), buffer.size());
}

std::error_code compression::io::FileHandler::write(const compression::common::Byte* data, size_t size) {
    if (!isOpen_ || !fileHandle_ || !data) {
        return compression::common::ErrorCode::FILE_WRITE_ERROR;
    }

    size_t bytesWritten = fwrite(data, 1, size, fileHandle_);
    if (bytesWritten != size) {
        return compression::common::ErrorCode::FILE_WRITE_ERROR;
    }

    fileSize_ += bytesWritten;
    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::FileHandler::seek(size_t position) {
    if (!isOpen_ || !fileHandle_) {
        return compression::common::ErrorCode::FILE_READ_ERROR;
    }

    if (fseek(fileHandle_, position, SEEK_SET) != 0) {
        return compression::common::ErrorCode::FILE_READ_ERROR;
    }

    return compression::common::ErrorCode::SUCCESS;
}

size_t compression::io::FileHandler::tell() const {
    if (!isOpen_ || !fileHandle_) {
        return 0;
    }

    long position = ftell(fileHandle_);
    return position >= 0 ? static_cast<size_t>(position) : 0;
}

bool compression::io::FileHandler::endOfFile() const {
    if (!isOpen_ || !fileHandle_) {
        return true;
    }

    return feof(fileHandle_) != 0;
}

bool compression::io::FileHandler::fileExists(const std::string& filePath) {
    FileEngine fileEngine;
    return fileEngine.exists(filePath);
}

std::error_code compression::io::FileHandler::getFileSize(const std::string& filePath, size_t& size) {
    FileEngine fileEngine;
    uint64_t fileSize = fileEngine.getFileSize(filePath);
    if (fileSize == 0 && !fileEngine.exists(filePath)) {
        return compression::common::ErrorCode::FILE_NOT_FOUND;
    }
    
    size = static_cast<size_t>(fileSize);
    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::FileHandler::deleteFile(const std::string& filePath) {
    FileEngine fileEngine;
    if (!fileEngine.deleteFile(filePath)) {
        return compression::common::ErrorCode::FILE_ACCESS_DENIED;
    }
    
    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::FileHandler::renameFile(const std::string& oldPath, const std::string& newPath) {
    FileEngine fileEngine;
    if (!fileEngine.renameFile(oldPath, newPath)) {
        return compression::common::ErrorCode::FILE_ACCESS_DENIED;
    }
    
    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::FileHandler::updateFileSize() {
    if (!fileExists(filePath_)) {
        return compression::common::ErrorCode::FILE_NOT_FOUND;
    }

    FileEngine fileEngine;
    uint64_t size = fileEngine.getFileSize(filePath_);
    fileSize_ = static_cast<size_t>(size);
    
    return compression::common::ErrorCode::SUCCESS;
}