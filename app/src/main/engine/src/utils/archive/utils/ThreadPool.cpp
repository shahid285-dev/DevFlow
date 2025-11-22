#include "../../include/utils/ThreadPool.hpp"

compression::utils::ThreadPool::ThreadPool(size_t numThreads)
    : stop_(false), activeTasks_(0), maxThreads_(numThread) {
    
    size_t hardwareThreads = std::thread::hardware_concurrency();
    size_t numWorkers = std::min(numThreads, hardwareThreads > 0 ? hardwareThreads : 2);
    numWorkers = std::max(numWorkers, static_cast<size_t>(1));
    
    workers_.reserve(numWorkers);
    for (size_t i = 0; i < numWorkers; ++i) {
        workers_.emplace_back(&ThreadPool::workerLoop, this);
    }
}

compression::utils::ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queueMutex_);
        stop_.store(true);
    }
    
    condition_.notify_all();
    
    for (std::thread& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void compression::utils::ThreadPool::workerLoop() {
    while (true) {
        std::function<void()> task;
        
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            
            condition_.wait(lock, [this]() {
                return stop_.load() || !tasks_.empty();
            });
            
            if (stop_.load() && tasks_.empty()) {
                return;
            }
            
            task = std::move(tasks_.front());
            tasks_.pop();
        }
        
        if (task) {
            activeTasks_.fetch_add(1);
            task();
            activeTasks_.fetch_sub(1);
        }
    }
}

size_t compression::utils::ThreadPool::getPendingTasks() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return tasks_.size();
}

void compression::utils::ThreadPool::waitAll() {
    while (true) {
        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (tasks_.empty() && activeTasks_.load() == 0) {
                break;
            }
        }
        std::this_thread::yield();
    }
}

void compression::utils::ThreadPool::resize(size_t numThreads) {
    if (numThreads == workers_.size()) {
        return;
    }
    
    {
        std::unique_lock<std::mutex> lock(queueMutex_);
        
        if (stop_.load()) {
            return;
        }
        
        size_t hardwareThreads = std::thread::hardware_concurrency();
        size_t newSize = std::min(numThreads, hardwareThreads > 0 ? hardwareThreads : 2);
        newSize = std::max(newSize, static_cast<size_t>(1));
        
        if (newSize > workers_.size()) {
            size_t toAdd = newSize - workers_.size();
            for (size_t i = 0; i < toAdd; ++i) {
                workers_.emplace_back(&ThreadPool::workerLoop, this);
            }
        } else if (newSize < workers_.size()) {
            size_t toRemove = workers_.size() - newSize;
            
            for (size_t i = 0; i < toRemove; ++i) {
                tasks_.emplace([](){ 
                    std::this_thread::yield();
                });
            }
            
            condition_.notify_all();
            
            for (size_t i = 0; i < toRemove; ++i) {
                if (workers_.back().joinable()) {
                    workers_.back().join();
                }
                workers_.pop_back();
            }
        }
        
        maxThreads_ = newSize;
    }
}
