#ifndef THREADPOOL_HPP
#define THREADPOOL_HPP

#include "../common/Types.hpp"
#include <vector>
#include <thread>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <future>

namespace compression {
namespace utils {

class ThreadPool : public common::NonCopyable {
private:
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queueMutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_;
    std::atomic<size_t> activeTasks_;
    size_t maxThreads_;
    
public:
    explicit ThreadPool(size_t numThreads = common::Constants::MAX_THREAD_POOL_SIZE);
    ~ThreadPool();
    
    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args) 
        -> std::future<typename std::result_of<F(Args...)>::type>;
    
    size_t getPendingTasks() const;
    size_t getActiveTasks() const { return activeTasks_; }
    size_t getThreadCount() const { return workers_.size(); }
    
    void waitAll();
    void resize(size_t numThreads);
    
private:
    void workerLoop();
};

template<class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) 
    -> std::future<typename std::result_of<F(Args...)>::type> {
    
    using return_type = typename std::result_of<F(Args...)>::type;
    
    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );
    
    std::future<return_type> result = task->get_future();
    
    {
        std::unique_lock<std::mutex> lock(queueMutex_);
        
        if (stop_) {
            throw std::runtime_error("enqueue on stopped ThreadPool");
        }
        
        tasks_.emplace([task](){ (*task)(); });
    }
    
    condition_.notify_one();
    return result;
}

} 
} 

#endif