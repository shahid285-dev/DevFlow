// include/common/MemoryPool.hpp
#ifndef MEMORYPOOL_HPP
#define MEMORYPOOL_HPP

#include "Types.hpp"
#include "ErrorCodes.hpp"
#include <vector>
#include <memory>
#include <mutex>
#include <queue>

namespace compression {
namespace common {

class MemoryPool : public NonCopyable {
private:
    struct PoolEntry {
        BytePtr buffer;
        size_t size;
        bool inUse;
        time_t lastUsed;
        
        PoolEntry(BytePtr buf, size_t sz) 
            : buffer(std::move(buf)), size(sz), inUse(false), lastUsed(0) {}
    };
    
    std::vector<PoolEntry> pool_;
    size_t maxPoolSize_;
    size_t maxBufferSize_;
    std::mutex mutex_;
    
public:
    explicit MemoryPool(size_t maxPoolSize = Constants::MEMORY_POOL_SIZE, 
                       size_t maxBufferSize = Constants::MAX_MEMORY_USAGE)
        : maxPoolSize_(maxPoolSize)
        , maxBufferSize_(maxBufferSize) {}
    
    ~MemoryPool() {
        clear();
    }
    
    BytePtr acquire(size_t size) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        if (size > maxBufferSize_) {
            return nullptr;
        }
        
        for (auto& entry : pool_) {
            if (!entry.inUse && entry.size >= size) {
                entry.inUse = true;
                entry.lastUsed = time(nullptr);
                return std::move(entry.buffer);
            }
        }
        
        if (pool_.size() < maxPoolSize_) {
            try {
                BytePtr newBuffer(new Byte[size]);
                pool_.emplace_back(std::move(newBuffer), size);
                pool_.back().inUse = true;
                pool_.back().lastUsed = time(nullptr);
                return std::move(pool_.back().buffer);
            } catch (const std::bad_alloc&) {
                return nullptr;
            }
        }
        
        return nullptr;
    }
    
    void release(BytePtr buffer, size_t size) {
        if (!buffer) return;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        for (auto& entry : pool_) {
            if (entry.buffer.get() == buffer.get()) {
                entry.inUse = false;
                entry.lastUsed = time(nullptr);
                entry.buffer = std::move(buffer);
                return;
            }
        }
        
        if (pool_.size() < maxPoolSize_) {
            pool_.emplace_back(std::move(buffer), size);
        }
    }
    
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.clear();
    }
    
    size_t getPoolSize() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pool_.size();
    }
    
    size_t getActiveBuffers() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& entry : pool_) {
            if (entry.inUse) count++;
        }
        return count;
    }
};

} // namespace common
} // namespace compression

#endif