#ifndef MEMORYBUFFER_HPP
#define MEMORYBUFFER_HPP

#include "../common/Types.hpp"
#include "../common/ErrorCodes.hpp"
#include "../common/MemoryPool.hpp"
#include <system_error>
#include <memory>

namespace compression {
namespace io {

class MemoryBuffer : public common::NonCopyable {
private:
    common::BytePtr data_;
    size_t capacity_;
    size_t size_;
    size_t position_;
    bool ownsMemory_;
    std::shared_ptr<common::MemoryPool> memoryPool_;
    
public:
    explicit MemoryBuffer(size_t initialCapacity = common::Constants::DEFAULT_CHUNK_SIZE,
                         std::shared_ptr<common::MemoryPool> pool = nullptr);
    MemoryBuffer(common::Byte* externalData, size_t size, bool takeOwnership = false);
    ~MemoryBuffer();
    
    std::error_code resize(size_t newCapacity);
    std::error_code reserve(size_t minCapacity);
    
    std::error_code write(const common::Byte* data, size_t size);
    std::error_code write(const common::ByteArray& data);
    std::error_code read(common::ByteArray& buffer, size_t bytesToRead);
    std::error_code read(common::Byte* buffer, size_t bytesToRead);
    
    std::error_code seek(size_t position);
    size_t tell() const { return position_; }
    size_t getSize() const { return size_; }
    size_t getCapacity() const { return capacity_; }
    const common::Byte* getData() const { return data_.get(); }
    common::Byte* getData() { return data_.get(); }
    
    common::ByteArray toByteArray() const;
    void clear();
    void reset();
    
    bool isReadable() const { return position_ < size_; }
    bool isWritable() const { return position_ <= capacity_; }
    
private:
    std::error_code ensureCapacity(size_t requiredCapacity);
};

} 
} 

#endif