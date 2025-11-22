#include "../../include/io/MemoryBuffer.hpp"
#include <cstring>
#include <algorithm>

compression::io::MemoryBuffer::MemoryBuffer(size_t initialCapacity, 
                                          std::shared_ptr<compression::common::MemoryPool> pool)
    : capacity_(0), size_(0), position_(0), ownsMemory_(true), memoryPool_(pool) {
    if (initialCapacity > 0) {
        resize(initialCapacity);
    }
}

compression::io::MemoryBuffer::MemoryBuffer(compression::common::Byte* externalData, size_t size, bool takeOwnership)
    : data_(takeOwnership ? externalData : nullptr), 
      capacity_(size), 
      size_(size), 
      position_(0),
      ownsMemory_(takeOwnership),
      memoryPool_(nullptr) {
    if (!takeOwnership) {
        data_ = std::unique_ptr<compression::common::Byte[]>(new compression::common::Byte[capacity_]);
        if (externalData && size > 0) {
            std::memcpy(data_.get(), externalData, size);
        }
    }
}

compression::io::MemoryBuffer::~MemoryBuffer() {
    if (data_ && ownsMemory_ && memoryPool_) {
        memoryPool_->release(std::move(data_), capacity_);
    }
}

std::error_code compression::io::MemoryBuffer::resize(size_t newCapacity) {
    if (newCapacity == capacity_) {
        return compression::common::ErrorCode::SUCCESS;
    }

    if (newCapacity == 0) {
        if (data_ && ownsMemory_ && memoryPool_) {
            memoryPool_->release(std::move(data_), capacity_);
        } else {
            data_.reset();
        }
        capacity_ = 0;
        size_ = 0;
        position_ = 0;
        return compression::common::ErrorCode::SUCCESS;
    }

    compression::common::BytePtr newData;
    
    if (memoryPool_) {
        newData = memoryPool_->acquire(newCapacity);
        if (!newData) {
            return compression::common::ErrorCode::MEMORY_ALLOCATION_FAILED;
        }
    } else {
        try {
            newData = std::unique_ptr<compression::common::Byte[]>(new compression::common::Byte[newCapacity]);
        } catch (const std::bad_alloc&) {
            return compression::common::ErrorCode::MEMORY_ALLOCATION_FAILED;
        }
    }

    if (data_ && size_ > 0) {
        size_t copySize = std::min(size_, newCapacity);
        std::memcpy(newData.get(), data_.get(), copySize);
        size_ = copySize;
        position_ = std::min(position_, size_);
    } else {
        size_ = 0;
        position_ = 0;
    }

    if (data_ && ownsMemory_ && memoryPool_) {
        memoryPool_->release(std::move(data_), capacity_);
    }
    
    data_ = std::move(newData);
    capacity_ = newCapacity;
    ownsMemory_ = true;

    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::MemoryBuffer::reserve(size_t minCapacity) {
    if (minCapacity <= capacity_) {
        return compression::common::ErrorCode::SUCCESS;
    }
    return resize(minCapacity);
}

std::error_code compression::io::MemoryBuffer::ensureCapacity(size_t requiredCapacity) {
    if (requiredCapacity <= capacity_) {
        return compression::common::ErrorCode::SUCCESS;
    }

    size_t newCapacity = capacity_ * 2;
    if (newCapacity < requiredCapacity) {
        newCapacity = requiredCapacity;
    }

    newCapacity = std::max(newCapacity, static_cast<size_t>(compression::common::Constants::MIN_CHUNK_SIZE));
    newCapacity = std::min(newCapacity, static_cast<size_t>(compression::common::Constants::MAX_MEMORY_USAGE));

    return resize(newCapacity);
}

std::error_code compression::io::MemoryBuffer::write(const compression::common::Byte* data, size_t size) {
    if (!data && size > 0) {
        return compression::common::ErrorCode::BUFFER_OVERFLOW;
    }

    if (size == 0) {
        return compression::common::ErrorCode::SUCCESS;
    }

    auto error = ensureCapacity(position_ + size);
    if (error) {
        return error;
    }

    std::memcpy(data_.get() + position_, data, size);
    position_ += size;
    size_ = std::max(size_, position_);

    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::MemoryBuffer::write(const compression::common::ByteArray& data) {
    return write(data.data(), data.size());
}

std::error_code compression::io::MemoryBuffer::read(compression::common::ByteArray& buffer, size_t bytesToRead) {
    if (bytesToRead == 0) {
        buffer.clear();
        return compression::common::ErrorCode::SUCCESS;
    }

    size_t available = size_ - position_;
    size_t readSize = std::min(bytesToRead, available);

    if (readSize == 0) {
        buffer.clear();
        return compression::common::ErrorCode::STREAM_END_UNEXPECTED;
    }

    buffer.resize(readSize);
    return read(buffer.data(), readSize);
}

std::error_code compression::io::MemoryBuffer::read(compression::common::Byte* buffer, size_t bytesToRead) {
    if (!buffer && bytesToRead > 0) {
        return compression::common::ErrorCode::BUFFER_OVERFLOW;
    }

    if (bytesToRead == 0) {
        return compression::common::ErrorCode::SUCCESS;
    }

    size_t available = size_ - position_;
    if (bytesToRead > available) {
        return compression::common::ErrorCode::BUFFER_UNDERFLOW;
    }

    std::memcpy(buffer, data_.get() + position_, bytesToRead);
    position_ += bytesToRead;

    return compression::common::ErrorCode::SUCCESS;
}

std::error_code compression::io::MemoryBuffer::seek(size_t position) {
    if (position > size_) {
        return compression::common::ErrorCode::BUFFER_OVERFLOW;
    }

    position_ = position;
    return compression::common::ErrorCode::SUCCESS;
}

compression::common::ByteArray compression::io::MemoryBuffer::toByteArray() const {
    compression::common::ByteArray result;
    if (size_ > 0) {
        result.resize(size_);
        std::memcpy(result.data(), data_.get(), size_);
    }
    return result;
}

void compression::io::MemoryBuffer::clear() {
    size_ = 0;
    position_ = 0;
}

void compression::io::MemoryBuffer::reset() {
    position_ = 0;
}